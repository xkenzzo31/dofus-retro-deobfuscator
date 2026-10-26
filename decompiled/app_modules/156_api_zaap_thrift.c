/* 156 [lit 8925, 3 args] <- anonymous_51 */
undefined4 156(undefined4 receiver,int a0,undefined4 a1,undefined4 a2)
{
  CreateFunctionContext(scope_156);
  _0x574a32 = Call(a2,0x25c2);
  iVar1 = Call(a2,0x1192);
  _0x5b7f29 = iVar1.ZaapService;
  uVar2 = CreateClosure(anonymous_8931);
  a0.exports.initConnect = uVar2;
  uVar2 = CreateClosure(anonymous_8952);
  a0.exports.connect = uVar2;
  uVar2 = CreateClosure(anonymous_8958);
  a0.exports.auth = uVar2;
  return undefined;
}
/* anonymous_8931 [lit 8931, 0 args] <- 156 */
undefined4 anonymous_8931(undefined4 receiver)
{
  iVar4 = _0x574a32;
  CreateFunctionContext(scope_anonymous_8931);
  uVar1 = CreateClosure(anonymous_8932);
  iVar2 = Call(uVar1);
  uVar1 = iVar2.port;
  _0x51e30c = iVar2.gameRelease;
  _0x1cbae8 = iVar2.instanceId;
  _0x21332e = iVar2.gameInstanceKey;
  uVar3 = _0x574a32.createConnection;
  iVar2 = CreateObjectLiteral({transport, protocol});
  _0x2721bc = uVar1;
  iVar2.transport = _0x574a32.TBufferedTransport;
  iVar2.protocol = _0x574a32.TBinaryProtocol;
  iVar4 = CallProperty(uVar3,iVar4,"localhost",uVar1,iVar2);
  uVar1 = CreateClosure(anonymous_8946);
  CallProperty(iVar4.on,iVar4,"error",uVar1);
  _0xb4e5de = CallProperty(_0x574a32.createClient,_0x574a32,_0x5b7f29,iVar4);
  return undefined;
}
/* anonymous_8932 [lit 8932, 0 args] <- anonymous_8931 */
undefined4 anonymous_8932(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_8932);
  _0x4d3d77 = CreateEmptyObjectLiteral();
  iVar1 = process.argv;
  iVar1 = CallProperty(iVar1.slice,iVar1,1);
  uVar2 = CreateClosure(anonymous_8936);
  CallProperty(iVar1.forEach,iVar1,uVar2);
  return _0x4d3d77;
}
/* anonymous_8936 [lit 8936, 1 args] <- anonymous_8932 */
undefined4 anonymous_8936(undefined4 receiver,int a0)
{
  boolean bVar1;
  CreateFunctionContext(scope_anonymous_8936);
  iVar2 = CallProperty(a0.startsWith,a0,"--");
  if ((iVar2 == 0) || (iVar2 = CallProperty(a0.includes,a0,"="), iVar2 == 0)) goto LAB_1096baa2;
  iVar2 = CallProperty(a0.slice,a0,2);
  uVar3 = CallProperty(iVar2.split,iVar2,"=");
  iVar2 = GetIterator(uVar3);
  bVar1 = (boolean)IsJSReceiver(iVar2);
  if (!bVar1) {
    iVar2 = CallRuntime(%ThrowSymbolIteratorInvalid);
  }
  uVar3 = iVar2.next;
  iVar4 = false;
  if (iVar4 == 0) {
    iVar4 = true;
    iVar5 = CallProperty(uVar3,iVar2);
    bVar1 = (boolean)IsJSReceiver(iVar5);
    if (!bVar1) {
      CallRuntime(%ThrowIteratorResultNotAnObject,iVar5);
    }
    if (iVar5.done != 0) goto LAB_1096ba23;
    uVar6 = iVar5.value;
    iVar4 = false;
  }
  else {
LAB_1096ba23:
    uVar6 = undefined;
  }
  if (iVar4 == 0) {
    iVar4 = true;
    iVar5 = CallProperty(uVar3,iVar2);
    bVar1 = (boolean)IsJSReceiver(iVar5);
    if (!bVar1) {
      CallRuntime(%ThrowIteratorResultNotAnObject,iVar5);
    }
    if (iVar5.done != 0) goto LAB_1096ba4d;
    uVar3 = iVar5.value;
    iVar4 = false;
  }
  else {
LAB_1096ba4d:
    uVar3 = undefined;
  }
  if (iVar4 == 0) {
    iVar4 = iVar2.return;
    if ((iVar4 != undefined) && (iVar4 != null)) {
      uVar7 = CallProperty(iVar4,iVar2);
      bVar1 = (boolean)IsJSReceiver(uVar7);
      if (!bVar1) {
        CallRuntime(%ThrowIteratorResultNotAnObject,uVar7);
      }
    }
  }
  SetProperty(_0x4d3d77,uVar6,uVar3);
LAB_1096baa2:
  return undefined;
}
/* anonymous_8946 [lit 8946, 1 args] <- anonymous_8931 */
undefined4 anonymous_8946(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_8946);
  CallProperty(console.log,console,"[Electron] Thirft error:" + a0.message);
  return undefined;
}
/* WARNING: Switch with 1 destination removed at 0x1096cc66 */
/* anonymous_8952 [lit 8952, 0 args] <- 156 */
undefined4 anonymous_8952(undefined4 receiver)
{
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar1 = CreateFunctionContext(scope_anonymous_8952);
    uVar2 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
    uVar3 = CreateClosure(_0x4c2fc2);
    uVar4 = CreateClosure(_0x5ec7e0);
    uVar5 = CreateClosure(_0x4e5a44);
    uVar6 = CreateClosure(_0x1746ac);
    uVar7 = CallProperty(_0xb4e5de.connect,_0xb4e5de,"retro",_0x51e30c,_0x1cbae8,_0x21332e);
    uVar7 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar2,uVar7);
    SuspendGenerator(uVar2,uVar2,uVar3,uVar4,in_r3,uVar5,uVar6,in_context,uVar1);
    return uVar7;
  }
  GeneratorResumeTarget(in_r0,0,1);
  uVar1 = ResumeGenerator(in_r0,0);
  ResumeGenerator(uVar1,1);
  ResumeGenerator(uVar1,2);
  ResumeGenerator(uVar1,3);
  ResumeGenerator(uVar1,4);
  ResumeGenerator(uVar1,5);
  ResumeGenerator(uVar1,6);
  ResumeGenerator(uVar1,7);
  iVar8 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar1);
  if (iVar8 == 0) {
    iVar8 = api.gameWindow.webContents;
    CallProperty(iVar8.send,iVar8,"onZaapConnect",in_acc);
    uVar1 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar1,undefined,true);
    return uVar1;
  }
  ReThrow(in_acc);
  return in_acc;
}
/* WARNING: Switch with 1 destination removed at 0x1096d6b6 */
/* anonymous_8958 [lit 8958, 1 args] <- 156 */
undefined4 anonymous_8958(undefined4 receiver,undefined4 a0)
{
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar1 = CreateFunctionContext(scope_anonymous_8958);
    uVar2 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
    uVar3 = CreateClosure(_0x1ab351);
    uVar4 = CreateClosure(_0x3bea41);
    uVar5 = CreateClosure(_0x1fc1bd);
    uVar6 = CallProperty(_0xb4e5de.auth_getGameToken,_0xb4e5de,a0,0x65);
    uVar6 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar2,uVar6);
    SuspendGenerator(uVar2,uVar2,uVar3,uVar4,in_r3,uVar5,in_context,uVar1);
    return uVar6;
  }
  GeneratorResumeTarget(in_r0,0,1);
  uVar1 = ResumeGenerator(in_r0,0);
  ResumeGenerator(uVar1,1);
  ResumeGenerator(uVar1,2);
  ResumeGenerator(uVar1,3);
  ResumeGenerator(uVar1,4);
  ResumeGenerator(uVar1,5);
  ResumeGenerator(uVar1,6);
  iVar7 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar1);
  if (iVar7 == 0) {
    iVar7 = api.gameWindow.webContents;
    CallProperty(iVar7.send,iVar7,"onZaapAuth",in_acc);
    uVar1 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar1,undefined,true);
    return uVar1;
  }
  ReThrow(in_acc);
  return in_acc;
}
