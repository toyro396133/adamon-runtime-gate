using System;using System.Reflection;using System.Threading;using Newtonsoft.Json.Linq;using GitHub.Runner.Common;
public static class TransportHarness {
 public static int Main(string[] args) {
  try {
   if(args[0]=="--validate") { P4ProtectedBridge.ValidateAssignment(args[1]); return 0; }
   int fd=int.Parse(args[0]);var request=JObject.Parse(args[1]);
   int[] descriptors=args.Length==4?new[]{int.Parse(args[2]),int.Parse(args[3])}:null;
   var flags=BindingFlags.NonPublic|BindingFlags.Static;
   typeof(P4ProtectedBridge).GetMethod("Send",flags).Invoke(null,new object[]{fd,request,descriptors});
   using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(3));
   var result=typeof(P4ProtectedBridge).GetMethod("Receive",flags).Invoke(null,new object[]{fd,request,timeout.Token});
   Console.WriteLine(((JObject)result).ToString(Newtonsoft.Json.Formatting.None));return 0;
  }catch(Exception ex){Console.Error.WriteLine(ex.InnerException?.Message??ex.Message);return 1;}
 }
}
