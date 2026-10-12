// Pinned Runner bridge. No workflow-controlled address, path, command or bootstrap FD.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using GitHub.DistributedTask.ObjectTemplating.Tokens;
using GitHub.DistributedTask.Pipelines;
using GitHub.Runner.Sdk;
using GitHub.Services.WebApi;
using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace GitHub.Runner.Common
{
    public static class P4ProtectedBridge
    {
        public const string Marker = "ADAMON_P4_FIXED_LAUNCH_V4";
        private const int ListenerFd = 198, WorkerFd = 199, MaxFrame = 1024 * 1024;
        private static string rawAssignment;
        private static Guid approvedStep;
        private static bool authorized;
        private static readonly object WriteLock = new object();
        public static string ListenerAssignment { get; private set; }

        [StructLayout(LayoutKind.Sequential)] private struct IOV { public IntPtr Base; public UIntPtr Length; }
        [StructLayout(LayoutKind.Sequential)] private struct MSG {
            public IntPtr Name; public uint NameLength; public IntPtr Vector;
            public UIntPtr VectorLength; public IntPtr Control; public UIntPtr ControlLength; public int Flags;
        }
        [DllImport("libc", SetLastError=true)] private static extern IntPtr sendmsg(int fd, ref MSG message, int flags);
        [DllImport("libc", SetLastError=true)] private static extern IntPtr recv(int fd, byte[] bytes, UIntPtr length, int flags);
        [DllImport("libc", SetLastError=true)] private static extern int getsockopt(int fd, int level, int option, out int value, ref uint length);
        [DllImport("libc", SetLastError=true)] private static extern int poll(IntPtr fds, uint count, int timeout);
        [StructLayout(LayoutKind.Sequential)] private struct PollFd { public int Fd; public short Events; public short Returned; }

        private static void VerifyFd(int fd) {
            if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("P4_LINUX_REQUIRED");
            uint size=4;
            if (getsockopt(fd,1,3,out int type,ref size)!=0 || type!=1)
                throw new InvalidOperationException("P4_PRIVATE_STREAM_REQUIRED");
            // FD provenance is supervisor-owned; a socket alone NEVER enrolls a process.
        }
        private static string Digest(string raw) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        private static JObject Request(string op, JObject payload) => new JObject {
            ["version"]=1,["operation"]=op,["request_id"]=Guid.NewGuid().ToString(),["payload"]=payload
        };
        private static void Send(int fd,JObject request,int[] descriptors=null) {
            VerifyFd(fd);
            byte[] body=Encoding.UTF8.GetBytes(request.ToString(Formatting.None));
            if(body.Length==0 || body.Length>MaxFrame) throw new InvalidOperationException("P4_FRAME_SIZE");
            byte[] frame=new byte[body.Length+4];
            frame[0]=(byte)(body.Length>>24);frame[1]=(byte)(body.Length>>16);frame[2]=(byte)(body.Length>>8);frame[3]=(byte)body.Length;
            Array.Copy(body,0,frame,4,body.Length);
            GCHandle pinned=GCHandle.Alloc(frame,GCHandleType.Pinned);
            IntPtr vector=IntPtr.Zero,control=IntPtr.Zero;
            lock(WriteLock) try {
                vector=Marshal.AllocHGlobal(Marshal.SizeOf<IOV>());
                Marshal.StructureToPtr(new IOV{Base=pinned.AddrOfPinnedObject(),Length=(UIntPtr)frame.Length},vector,false);
                int controlSize=0;
                if(descriptors!=null) {
                    if(descriptors.Length!=2 || descriptors[0]<0 || descriptors[1]<0 || descriptors[0]==descriptors[1])
                        throw new InvalidOperationException("P4_PIPE_FDS");
                    // Linux x86_64/aarch64 cmsghdr: size_t + int + int, aligned to8.
                    if(IntPtr.Size!=8) throw new InvalidOperationException("P4_64BIT_REQUIRED");
                    controlSize=24;control=Marshal.AllocHGlobal(controlSize);
                    for(int i=0;i<controlSize;i++) Marshal.WriteByte(control,i,0);
                    Marshal.WriteInt64(control,24);Marshal.WriteInt32(control,8,1);Marshal.WriteInt32(control,12,1);
                    Marshal.WriteInt32(control,16,descriptors[0]);Marshal.WriteInt32(control,20,descriptors[1]);
                }
                var message=new MSG{Vector=vector,VectorLength=(UIntPtr)1,Control=control,ControlLength=(UIntPtr)controlSize};
                long count=sendmsg(fd,ref message,0x4000).ToInt64(); // MSG_NOSIGNAL
                // Partial writes deny; never retry ancillary rights and accidentally duplicate them.
                if(count!=frame.Length) throw new InvalidOperationException("P4_SEND_FAILED");
            } finally { if(control!=IntPtr.Zero) Marshal.FreeHGlobal(control);if(vector!=IntPtr.Zero) Marshal.FreeHGlobal(vector);pinned.Free(); }
        }
        private static byte[] Read(int fd,int length,CancellationToken token) {
            byte[] output=new byte[length];int position=0;
            IntPtr polling=Marshal.AllocHGlobal(Marshal.SizeOf<PollFd>());
            try { while(position<length) {
                token.ThrowIfCancellationRequested();
                Marshal.StructureToPtr(new PollFd{Fd=fd,Events=1},polling,false);
                int ready=poll(polling,1,250);
                if(ready<0) throw new InvalidOperationException("P4_POLL_FAILED");
                if(ready==0) continue;
                byte[] part=new byte[length-position];long read=recv(fd,part,(UIntPtr)part.Length,0).ToInt64();
                if(read<=0) throw new InvalidOperationException("P4_CHANNEL_CLOSED");
                Array.Copy(part,0,output,position,(int)read);position+=(int)read;
            } return output; } finally {Marshal.FreeHGlobal(polling);}
        }
        private static JObject Receive(int fd,JObject request,CancellationToken token) {
            byte[] head=Read(fd,4,token);long length=((long)head[0]<<24)|((long)head[1]<<16)|((long)head[2]<<8)|head[3];
            if(length<=0 || length>MaxFrame) throw new InvalidOperationException("P4_FRAME_SIZE");
            var response=JObject.Parse(new UTF8Encoding(false,true).GetString(Read(fd,(int)length,token)),
                new JsonLoadSettings{DuplicatePropertyNameHandling=DuplicatePropertyNameHandling.Error});
            var fields=new HashSet<string>{"version","operation","request_id","status","exit_code"};
            foreach(var p in response.Properties()) if(!fields.Remove(p.Name)) throw new InvalidOperationException("P4_RESPONSE_FIELDS");
            if(fields.Count!=0 || response["version"].Type!=JTokenType.Integer || (int?)response["version"]!=1 || !JToken.DeepEquals(response["operation"],request["operation"]) || !JToken.DeepEquals(response["request_id"],request["request_id"]))
                throw new InvalidOperationException("P4_RESPONSE_BINDING");
            string status=(string)response["status"];
            if(status!="COMPLETE") throw new InvalidOperationException("P4_SUPERVISOR_DENIED");
            if(response["exit_code"].Type!=JTokenType.Integer || (int)response["exit_code"]<0 || (int)response["exit_code"]>255)
                throw new InvalidOperationException("P4_EXIT_CODE");
            return response;
        }
        private static async Task<JObject> Call(int fd,string op,JObject payload,CancellationToken token,int[] descriptors=null) {
            var request=Request(op,payload);Send(fd,request,descriptors);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            if(op=="worker_ack" || op=="authorize_assignment") timeout.CancelAfter(TimeSpan.FromSeconds(30));
            var reply=await Task.Run(()=>Receive(fd,request,timeout.Token),timeout.Token);
            if((op=="worker_ack" || op=="authorize_assignment") && (int)reply["exit_code"]!=0)
                throw new InvalidOperationException("P4_BOOTSTRAP_DENIED");
            return reply;
        }
        public static async Task<int> SpawnWorkerAsync(string raw,string pipeIn,string pipeOut,CancellationToken token) {
            ValidateAssignment(raw);ListenerAssignment=raw;
            if(!int.TryParse(pipeIn,out int input) || !int.TryParse(pipeOut,out int output)) throw new InvalidOperationException("P4_PIPE_FDS");
            using var cancelled=token.Register(()=>RevokeListener());
            var result=await Call(ListenerFd,"listener_snapshot_spawn",new JObject{["raw_assignment"]=raw,["assignment_sha256"]=Digest(raw)},token,new[]{input,output});
            return (int)result["exit_code"];
        }
        public static async Task AcknowledgeWorkerAsync(string raw) {
            ValidateAssignment(raw);
            await Call(WorkerFd,"worker_ack",new JObject{["raw_assignment"]=raw,["assignment_sha256"]=Digest(raw)},CancellationToken.None);
            rawAssignment=raw;
        }
        public static async Task AuthorizeAssignmentAsync(string serialized) {
            if(rawAssignment==null) throw new InvalidOperationException("P4_NO_BOOTSTRAP");
            var snapshot = StringUtil.ConvertFromJson<AgentJobRequestMessage>(rawAssignment);
            if(!JToken.DeepEquals(JObject.Parse(JsonUtility.ToString(snapshot)), JObject.Parse(serialized)))
                throw new InvalidOperationException("P4_ASSIGNMENT_MUTATION");
            ValidateAssignment(serialized);
            // Re-serialization is not the raw snapshot; original digest remains the authority.
            await Call(WorkerFd,"authorize_assignment",new JObject{["assignment_sha256"]=Digest(rawAssignment),["step_id"]=approvedStep.ToString()},CancellationToken.None);
            authorized=true;
        }
        public static async Task ExecuteFixedStepAsync(string id,CancellationToken token) {
            if(!authorized || id!=approvedStep.ToString()) throw new InvalidOperationException("P4_UNAUTHORIZED_STEP");
            using var cancelled=token.Register(()=>RevokeWorker("cancel"));
            var reply=await Call(WorkerFd,"fixed_step_execute",new JObject{["assignment_sha256"]=Digest(rawAssignment),["step_id"]=id},token);
            if((int)reply["exit_code"]!=0) throw new InvalidOperationException("P4_ROLE_FAILED");
        }
        public static void RevokeListener() => Revoke(ListenerFd,"bridge_failure");
        public static void RevokeWorker(string reason) {authorized=false;Revoke(WorkerFd,reason);}
        private static void Revoke(int fd,string reason) {
            try {Send(fd,Request("revoke",new JObject{["reason"]=reason}));}
            catch { /* Supervisor watches process/pidfd/channel death independently. No compute fallback. */ }
        }
        public static void ValidateAssignment(string raw) {
            try { ValidateAssignmentCore(raw); }
            catch (JsonException) { throw new InvalidOperationException("P4_INVALID_ASSIGNMENT_JSON"); }
            catch (FormatException) { throw new InvalidOperationException("P4_INVALID_ASSIGNMENT_FORMAT"); }
        }
        private static void ValidateAssignmentCore(string raw) {
            // Duplicate JSON is rejected before typed deserialization to prevent competing meanings.
            JObject.Parse(raw,new JsonLoadSettings{DuplicatePropertyNameHandling=DuplicatePropertyNameHandling.Error});
            var message=StringUtil.ConvertFromJson<AgentJobRequestMessage>(raw);
            if(message==null || message.JobId==Guid.Empty || message.RequestId<=0 || message.Plan==null || message.Plan.PlanId==Guid.Empty || message.ContextData==null || !message.ContextData.ContainsKey("github") || message.Steps?.Count!=1)
                throw new InvalidOperationException("P4_ASSIGNMENT_SHAPE");
            if(message.JobContainer!=null || message.JobServiceContainers!=null || message.EnvironmentVariables?.Count>0 || message.Defaults?.Count>0 || message.EnableDebugger || message.DebuggerTunnel!=null || message.Snapshot!=null || message.JobOutputs!=null || message.ActionsEnvironment!=null)
                throw new InvalidOperationException("P4_JOB_OVERRIDE");
            if(message.Steps[0] is not ActionStep step || step.Id==Guid.Empty || string.IsNullOrEmpty(step.ContextName) || step.Reference is not ScriptReference || !step.Enabled || step.Background || step.Environment!=null || step.ContinueOnError!=null || step.TimeoutInMinutes!=null || step.ParallelGroupId!=null || step.Condition!="success()")
                throw new InvalidOperationException("P4_STEP_SHAPE");
            if(step.Inputs is not MappingToken inputs || inputs.Count()!=1 || inputs[0].Key is not StringToken key || key.Value!="script" || inputs[0].Value is not StringToken value || value.Value!=Marker)
                throw new InvalidOperationException("P4_LITERAL_MARKER_REQUIRED");
            foreach(System.Collections.DictionaryEntry variable in Environment.GetEnvironmentVariables())
                if(((string)variable.Key).StartsWith("ACTIONS_RUNNER_HOOK_",StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("P4_HOOK_DENIED");
            approvedStep=step.Id;
        }
    }
}
