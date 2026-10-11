// Compile-only shapes for public upstream SDK types. NOT a fork compatibility test.
using System;using System.Collections.Generic;using Newtonsoft.Json;
namespace GitHub.DistributedTask.ObjectTemplating.Tokens {
 public class TemplateToken {} public class StringToken:TemplateToken {public string Value{get;set;}}
 public class MappingToken:TemplateToken, System.Collections.Generic.IEnumerable<KeyValuePair<TemplateToken,TemplateToken>> {public List<KeyValuePair<TemplateToken,TemplateToken>> Pairs=new();public int Count=>Pairs.Count;public KeyValuePair<TemplateToken,TemplateToken> this[int n]=>Pairs[n];public IEnumerator<KeyValuePair<TemplateToken,TemplateToken>> GetEnumerator()=>Pairs.GetEnumerator();System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()=>GetEnumerator();}
}
namespace GitHub.DistributedTask.Pipelines {
 using GitHub.DistributedTask.ObjectTemplating.Tokens;
 public class Plan {public Guid PlanId{get;set;}}
 public class JobStep {} public class ScriptReference {}
 public class ActionStep:JobStep {public Guid Id{get;set;} public string ContextName{get;set;} public object Reference{get;set;} public bool Enabled{get;set;} public bool Background{get;set;} public TemplateToken Environment{get;set;} public TemplateToken ContinueOnError{get;set;} public TemplateToken TimeoutInMinutes{get;set;} public string ParallelGroupId{get;set;} public string Condition{get;set;} public TemplateToken Inputs{get;set;}}
 public class AgentJobRequestMessage {public Guid JobId{get;set;} public long RequestId{get;set;} public bool EnableDebugger{get;set;} public object DebuggerTunnel{get;set;} public object Snapshot{get;set;} public object JobOutputs{get;set;} public object ActionsEnvironment{get;set;} public Plan Plan{get;set;} public Dictionary<string,object> ContextData{get;set;} public List<JobStep> Steps{get;set;} public TemplateToken JobContainer{get;set;} public TemplateToken JobServiceContainers{get;set;} public List<TemplateToken> EnvironmentVariables{get;set;} public List<TemplateToken> Defaults{get;set;}}
}
namespace GitHub.Runner.Sdk {public static class StringUtil {public static T ConvertFromJson<T>(string s)=>JsonConvert.DeserializeObject<T>(s);}}
namespace GitHub.Services.WebApi {public static class JsonUtility {public static string ToString(object x)=>JsonConvert.SerializeObject(x);}}
