/* 4288 [lit 8848, 3 args] <- anonymous_51 */
undefined4 4288(undefined4 receiver,int a0,undefined4 a1,undefined4 a2)
{
  CreateFunctionContext(scope_4288);
  iVar1 = Call(a2,0x2518);
  _0x425da6 = iVar1.app;
  _0x404a76 = iVar1.shell;
  _0x1ee583 = Call(a2,0x3f9);
  iVar1 = Call(a2,0x3f9);
  _0x33c862 = iVar1.resolve;
  _0x1305ea = Call(a2,0x1beb);
  Call(a2,0x1beb);
  iVar1 = Call(a2,0x1beb);
  _0x455b7c = iVar1.promises.readdir;
  uVar2 = CreateClosure(anonymous_8850);
  a0.exports.randomInt = uVar2;
  uVar2 = CreateClosure(anonymous_8853);
  a0.exports.getDirectories = uVar2;
  uVar2 = CreateClosure(anonymous_8859);
  a0.exports.copyFile = uVar2;
  uVar2 = CreateClosure(anonymous_8863);
  a0.exports.openUrlExternal = uVar2;
  uVar2 = CreateClosure(anonymous_8865);
  a0.exports.writeLog = uVar2;
  uVar2 = CreateClosure(anonymous_8883);
  a0.exports.createDir = uVar2;
  _0x56addb = CreateEmptyObjectLiteral();
  a0.exports.externalInterfaceUnescape = _0x5da57d;
  uVar2 = CreateClosure(anonymous_8906);
  a0.exports.cleanPacket = uVar2;
  a0.exports.colorShade = _0xb8d7d0;
  uVar2 = CreateClosure(anonymous_8911);
  a0.exports.applyDarkMode = uVar2;
  uVar2 = CreateClosure(anonymous_8912);
  a0.exports.getKeyFromCharCode = uVar2;
  uVar2 = CreateClosure(anonymous_8914);
  a0.exports.getYesterdayDate = uVar2;
  uVar2 = CreateClosure(anonymous_8917);
  a0.exports.getCurrentDate = uVar2;
  uVar2 = CreateClosure(anonymous_8919);
  a0.exports.checkClientLanguage = uVar2;
  uVar2 = CreateClosure(_0x57c5e2);
  a0.exports.getFiles = uVar2;
  return undefined;
}
/* _0x5da57d [lit 8888, 1 args] <- 4288 */
undefined4 _0x5da57d(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope__0x5da57d);
  iVar1 = CallProperty(a0.replaceAll,a0,"&ASamp;","&amp;");
  iVar1 = CallProperty(iVar1.replaceAll,iVar1,"&ASlt;","&lt;");
  uVar2 = CallProperty(iVar1.replaceAll,iVar1,"&ASgt;","&gt;");
  return uVar2;
}
/* _0xb8d7d0 [lit 8894, 2 args] <- 4288 */
char[] _0xb8d7d0(undefined4 receiver,int a0,int a1)
{
  boolean bVar2;
  CreateFunctionContext(scope__0xb8d7d0);
  uVar3 = CreateRegExpLiteral("^#",0);
  iVar4 = CallProperty(a0.replace,a0,uVar3,"");
  cVar1 = LooseEquals("111111",iVar4);
  if ((((cVar1 != '\0') || (cVar1 = LooseEquals("232323",iVar4), cVar1 != '\0')) ||
      (cVar1 = LooseEquals("222222",iVar4), cVar1 != '\0')) ||
     (cVar1 = LooseEquals("000000",iVar4), cVar1 != '\0')) {
    return "#FFFFFF";
  }
  cVar1 = LooseEquals("006699",iVar4);
  if (cVar1 != '\0') {
    return "#86CDF0";
  }
  if (iVar4.length == 3) {
    iVar5 = GetProperty(iVar4,0);
    iVar6 = GetProperty(iVar4,0);
    iVar7 = GetProperty(iVar4,1);
    iVar8 = GetProperty(iVar4,1);
    iVar9 = GetProperty(iVar4,2);
    iVar4 = GetProperty(iVar4,2);
    iVar4 = iVar5 + iVar6 + iVar7 + iVar8 + iVar9 + iVar4;
  }
  uVar3 = CreateRegExpLiteral(".{2}",1);
  uVar3 = CallProperty(iVar4.match,iVar4,uVar3);
  iVar4 = GetIterator(uVar3);
  bVar2 = (boolean)IsJSReceiver(iVar4);
  if (!bVar2) {
    iVar4 = CallRuntime(%ThrowSymbolIteratorInvalid);
  }
  uVar3 = iVar4.next;
  iVar5 = false;
  if (iVar5 == 0) {
    iVar5 = true;
    iVar6 = CallProperty(uVar3,iVar4);
    bVar2 = (boolean)IsJSReceiver(iVar6);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,iVar6);
    }
    if (iVar6.done != 0) goto LAB_10960cfc;
    uVar10 = iVar6.value;
    iVar5 = false;
  }
  else {
LAB_10960cfc:
    uVar10 = undefined;
  }
  if (iVar5 == 0) {
    iVar5 = true;
    iVar6 = CallProperty(uVar3,iVar4);
    bVar2 = (boolean)IsJSReceiver(iVar6);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,iVar6);
    }
    if (iVar6.done != 0) goto LAB_10960d26;
    uVar11 = iVar6.value;
    iVar5 = false;
  }
  else {
LAB_10960d26:
    uVar11 = undefined;
  }
  if (iVar5 == 0) {
    iVar5 = true;
    iVar6 = CallProperty(uVar3,iVar4);
    bVar2 = (boolean)IsJSReceiver(iVar6);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,iVar6);
    }
    if (iVar6.done != 0) goto LAB_10960d50;
    uVar3 = iVar6.value;
    iVar5 = false;
  }
  else {
LAB_10960d50:
    uVar3 = undefined;
  }
  if (iVar5 == 0) {
    iVar5 = iVar4.return;
    if ((iVar5 != undefined) && (iVar5 != null)) {
      uVar12 = CallProperty(iVar5,iVar4);
      bVar2 = (boolean)IsJSReceiver(uVar12);
      if (!bVar2) {
        CallRuntime(%ThrowIteratorResultNotAnObject,uVar12);
      }
    }
  }
  uVar12 = CreateArrayLiteral(ArrayBoilerplateDescription);
  iVar4 = Call(parseInt,uVar10,0x10);
  SetProperty(uVar12,0,iVar4 + a1);
  iVar4 = Call(parseInt,uVar11,0x10);
  SetProperty(uVar12,1,iVar4 + a1);
  iVar4 = Call(parseInt,uVar3,0x10);
  SetProperty(uVar12,2,iVar4 + a1);
  iVar4 = GetIterator(uVar12);
  bVar2 = (boolean)IsJSReceiver(iVar4);
  if (!bVar2) {
    iVar4 = CallRuntime(%ThrowSymbolIteratorInvalid);
  }
  uVar3 = iVar4.next;
  iVar5 = false;
  if (iVar5 == 0) {
    iVar5 = true;
    iVar6 = CallProperty(uVar3,iVar4);
    bVar2 = (boolean)IsJSReceiver(iVar6);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,iVar6);
    }
    if (iVar6.done != 0) goto LAB_10960e36;
    uVar10 = iVar6.value;
    iVar5 = false;
  }
  else {
LAB_10960e36:
    uVar10 = undefined;
  }
  if (iVar5 == 0) {
    iVar5 = true;
    iVar6 = CallProperty(uVar3,iVar4);
    bVar2 = (boolean)IsJSReceiver(iVar6);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,iVar6);
    }
    if (iVar6.done != 0) goto LAB_10960e60;
    uVar11 = iVar6.value;
    iVar5 = false;
  }
  else {
LAB_10960e60:
    uVar11 = undefined;
  }
  if (iVar5 == 0) {
    iVar5 = true;
    iVar6 = CallProperty(uVar3,iVar4);
    bVar2 = (boolean)IsJSReceiver(iVar6);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,iVar6);
    }
    if (iVar6.done == 0) {
      uVar3 = iVar6.value;
      iVar5 = false;
      goto LAB_10960e8b;
    }
  }
  uVar3 = undefined;
LAB_10960e8b:
  if (iVar5 == 0) {
    iVar5 = iVar4.return;
    if ((iVar5 != undefined) && (iVar5 != null)) {
      uVar12 = CallProperty(iVar5,iVar4);
      bVar2 = (boolean)IsJSReceiver(uVar12);
      if (!bVar2) {
        CallRuntime(%ThrowIteratorResultNotAnObject,uVar12);
      }
    }
  }
  uVar10 = CallProperty(Math.min,Math,0xff,uVar10);
  iVar4 = CallProperty(Math.max,Math,uVar10,0);
  iVar4 = CallProperty(iVar4.toString,iVar4,0x10);
  uVar10 = CallProperty(Math.min,Math,0xff,uVar11);
  iVar5 = CallProperty(Math.max,Math,uVar10,0);
  iVar5 = CallProperty(iVar5.toString,iVar5,0x10);
  uVar3 = CallProperty(Math.min,Math,0xff,uVar3);
  iVar6 = CallProperty(Math.max,Math,uVar3,0);
  iVar6 = CallProperty(iVar6.toString,iVar6,0x10);
  if ((int)iVar4.length < 2) {
    pcVar13 = "0";
  }
  else {
    pcVar13 = "";
  }
  if ((int)iVar5.length < 2) {
    pcVar14 = "0";
  }
  else {
    pcVar14 = "";
  }
  if ((int)iVar6.length < 2) {
    pcVar15 = "0";
  }
  else {
    pcVar15 = "";
  }
  return "#" + pcVar13 + iVar4 + pcVar14 + iVar5 + pcVar15 + iVar6;
}
/* _0x3eaa06 [lit 8901, 1 args] <- 4288 */
char[] _0x3eaa06(undefined4 receiver,undefined4 a0)
{
  CreateFunctionContext(scope__0x3eaa06);
  iVar1 = Construct(Date,3,1);
  iVar2 = CallProperty(iVar1.getDate,iVar1);
  iVar3 = CallProperty(iVar1.getMonth,iVar1);
  iVar1 = CallProperty(iVar1.getFullYear,iVar1);
  return "-" + iVar3 + 1 + iVar1 + "-" + iVar2;
}
/* anonymous_8850 [lit 8850, 2 args] <- 4288 */
int anonymous_8850(undefined4 receiver,int a0,int a1)
{
  CreateFunctionContext(scope_anonymous_8850);
  iVar1 = CallProperty(Math.random,Math);
  iVar1 = CallProperty(Math.floor,Math,iVar1 * ((a1 - a0) + 1));
  return iVar1 + a0;
}
/* anonymous_8853 [lit 8853, 1 args] <- 4288 */
undefined4 anonymous_8853(undefined4 receiver,undefined4 a0)
{
  CreateFunctionContext(scope_anonymous_8853);
  _0x272253 = a0;
  iVar1 = CallProperty(_0x1305ea.readdirSync,_0x1305ea,a0);
  uVar2 = CreateClosure(anonymous_8856);
  uVar2 = CallProperty(iVar1.filter,iVar1,uVar2);
  return uVar2;
}
/* anonymous_8856 [lit 8856, 1 args] <- anonymous_8853 */
undefined4 anonymous_8856(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_8856);
  iVar1 = CallProperty(_0x1305ea.statSync,_0x1305ea,"/" + a0 + _0x272253);
  uVar2 = CallProperty(iVar1.isDirectory,iVar1);
  return uVar2;
}
/* anonymous_8859 [lit 8859, 2 args] <- 4288 */
undefined4 anonymous_8859(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_8859);
  uVar1 = CreateClosure(anonymous_8861);
  CallProperty(_0x1305ea.copyFile,_0x1305ea,a0,a1,uVar1);
  return undefined;
}
/* anonymous_8861 [lit 8861, 1 args] <- anonymous_8859 */
undefined4 anonymous_8861(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_8861);
  if (a0 != 0) {
    CallProperty(console.log,console,a0);
  }
  return undefined;
}
/* anonymous_8863 [lit 8863, 1 args] <- 4288 */
undefined4 anonymous_8863(undefined4 receiver,undefined4 a0)
{
  CallProperty(_0x404a76.openExternal,_0x404a76,a0);
  return undefined;
}
/* anonymous_8865 [lit 8865, 2 args] <- 4288 */
undefined4 anonymous_8865(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_8865);
  _0x1f7659 = a0;
  _0x3e2164 = a1;
  cVar1 = IsUndetectable(a0);
  if ((cVar1 == '\0') && (cVar1 = IsUndetectable(a1), cVar1 == '\0')) {
    uVar2 = CallProperty(_0x425da6.getPath,_0x425da6,"userData");
    _0x2fd1a1 = CallProperty(_0x1ee583.join,_0x1ee583,uVar2,"RetroLogs");
    uVar2 = CreateEmptyObjectLiteral();
    uVar3 = CreateClosure(anonymous_8871);
    CallProperty(_0x1305ea.mkdir,_0x1305ea,_0x2fd1a1,uVar2,uVar3);
  }
  return undefined;
}
/* anonymous_8871 [lit 8871, 1 args] <- anonymous_8865 */
int anonymous_8871(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_8871);
  if ((a0 != 0) && (cVar1 = LooseEquals("EEXIST",a0.code), cVar1 == '\0')) {
    Throw(a0);
    return a0;
  }
  iVar2 = api.utils;
  uVar3 = CallProperty(iVar2.getCurrentDate,iVar2);
  _0x2fd1a1 = CallProperty(_0x1ee583.join,_0x1ee583,_0x2fd1a1,uVar3);
  uVar3 = CreateEmptyObjectLiteral();
  uVar4 = CreateClosure(anonymous_8877);
  CallProperty(_0x1305ea.mkdir,_0x1305ea,_0x2fd1a1,uVar3,uVar4);
  return undefined;
}
/* anonymous_8877 [lit 8877, 1 args] <- anonymous_8871 */
int anonymous_8877(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_8877);
  if ((a0 != 0) && (cVar1 = LooseEquals("EEXIST",a0.code), cVar1 == '\0')) {
    Throw(a0);
    return a0;
  }
  uVar2 = CallProperty(_0x1ee583.join,_0x1ee583,_0x2fd1a1,"log_" + _0x1f7659 + ".txt");
  iVar3 = CreateEmptyObjectLiteral();
  iVar3.flags = "a";
  uVar4 = GetProperty(_0x56addb,uVar2);
  cVar1 = IsUndetectable(uVar4);
  if (cVar1 != '\0') {
    uVar4 = CallProperty(_0x1305ea.createWriteStream,_0x1305ea,uVar2,iVar3);
    SetProperty(_0x56addb,uVar2,uVar4);
  }
  iVar3 = GetProperty(_0x56addb,uVar2);
  CallProperty(iVar3.write,iVar3,"\n" + _0x3e2164);
  return undefined;
}
/* anonymous_8883 [lit 8883, 1 args] <- 4288 */
undefined4 anonymous_8883(undefined4 receiver,undefined4 a0)
{
  iVar1 = CallProperty(_0x1305ea.existsSync,_0x1305ea,a0);
  if (iVar1 == 0) {
    CallProperty(_0x1305ea.mkdirSync,_0x1305ea,a0);
  }
  return undefined;
}
/* anonymous_8906 [lit 8906, 1 args] <- 4288 */
undefined4 anonymous_8906(undefined4 receiver,undefined4 a0)
{
  CreateFunctionContext(scope_anonymous_8906);
  uVar1 = CreateClosure(anonymous_8907);
  uVar2 = Call(_0x5da57d,a0);
  uVar1 = Call(uVar1,uVar2);
  return uVar1;
}
/* anonymous_8907 [lit 8907, 1 args] <- anonymous_8906 */
int anonymous_8907(undefined4 receiver,int a0)
{
  uVar2 = GetProperty(a0,0);
  cVar1 = LooseEquals("ù",uVar2);
  if (cVar1 != '\0') {
    iVar3 = CallProperty(a0.indexOf,a0,"ù",2);
    a0 = CallProperty(a0.substring,a0,iVar3 + 1,a0.length);
  }
  return a0;
}
/* anonymous_8912 [lit 8912, 1 args] <- 4288 */
char[] anonymous_8912(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_8912);
  cVar1 = LooseEquals(0xde,a0);
  if (cVar1 == '\0') {
    if ((0x5f < a0) && (a0 < 0x6a)) {
      a0 = a0 + -0x30;
    }
    pcVar2 = CallProperty(String.fromCharCode,String,a0);
  }
  else {
    pcVar2 = "\'";
  }
  return pcVar2;
}
/* anonymous_8914 [lit 8914, 0 args] <- 4288 */
undefined4 anonymous_8914(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_8914);
  iVar1 = Construct(Date);
  iVar2 = CallProperty(iVar1.getDate,iVar1);
  uVar3 = CallProperty(iVar1.setDate,iVar1,iVar2 + -1);
  uVar3 = Call(_0x3eaa06,uVar3);
  return uVar3;
}
/* anonymous_8917 [lit 8917, 0 args] <- 4288 */
undefined4 anonymous_8917(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_8917);
  uVar1 = CallProperty(Date.now,Date);
  uVar1 = Call(_0x3eaa06,uVar1);
  return uVar1;
}
/* anonymous_8919 [lit 8919, 1 args] <- 4288 */
char[] anonymous_8919(undefined4 receiver,char[] a0)
{
  if ((((a0 != "de") && (a0 != "en")) && (a0 != "es")) &&
     (((a0 != "fr" && (a0 != "it")) && ((a0 != "nl" && (a0 != "pt")))))) {
    return "fr";
  }
  return a0;
}
/* _0x57c5e2 [lit 8920, 1 args] <- 4288 */
undefined4 _0x57c5e2(undefined4 receiver,undefined4 a0)
{
  boolean bVar1;
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar2 = CreateFunctionContext(scope__0x57c5e2);
    uVar3 = InvokeIntrinsic(%_CreateJSGeneratorObject,in_closure,receiver);
    a0_0x31e777 = the_hole;
    a0_0x200ab5 = the_hole;
    a0_0x1c07e7 = the_hole;
    a0_0x5c1a2e = the_hole;
    uVar4 = CreateClosure(_0x2d5d3a);
    uVar5 = CreateClosure(_0x35b94c);
    uVar6 = CreateClosure(_0x2ceccf);
    SuspendGenerator(uVar3,uVar3,in_r1,uVar4,uVar5,uVar6,in_r5,in_r6,in_closure,in_r8,in_r9,in_r10,
                     in_context,in_closure,receiver,uVar2,uVar2);
    return uVar3;
  }
  uVar2 = GeneratorResumeTarget(in_r0,0,7);
  switch(uVar2) {
  case 0x109680f1:
    uVar4 = ResumeGenerator(in_r0,0);
    ResumeGenerator(uVar4,1);
    uVar3 = ResumeGenerator(uVar4,2);
    uVar5 = ResumeGenerator(uVar4,3);
    uVar6 = ResumeGenerator(uVar4,4);
    uVar10 = ResumeGenerator(uVar4,5);
    uVar11 = ResumeGenerator(uVar4,6);
    uVar14 = ResumeGenerator(uVar4,7);
    uVar15 = ResumeGenerator(uVar4,8);
    uVar17 = ResumeGenerator(uVar4,9);
    uVar18 = ResumeGenerator(uVar4,10);
    uVar19 = ResumeGenerator(uVar4,0xb);
    uVar20 = ResumeGenerator(uVar4,0xc);
    uVar21 = ResumeGenerator(uVar4,0xd);
    uVar16 = ResumeGenerator(uVar4,0xe);
    uVar25 = ResumeGenerator(uVar4,0xf);
    uVar2 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar4);
                    /* WARNING: Switch is manually overridden */
    uVar2 = SwitchTarget(uVar2,0xb,2,0);
    switch(uVar2) {
    case 0x109680ff:
      Throw(in_acc);
      return in_acc;
    case 0x10968102:
      break;
    case 0x1096810b:
      iVar12 = CreateEmptyObjectLiteral();
      iVar12.withFileTypes = true;
      uVar2 = Call(_0x455b7c,a0,iVar12);
      uVar2 = InvokeIntrinsic(%_AsyncGeneratorAwaitUncaught,uVar4,uVar2);
      SuspendGenerator(uVar4,uVar4,iVar12,uVar3,uVar5,uVar6,uVar10,uVar11,uVar14,uVar15,uVar17,
                       uVar18,uVar19,uVar20,uVar21,uVar16,uVar25);
      return uVar2;
    }
    goto LAB_109684b2;
  case 0x109681bb:
    uVar4 = ResumeGenerator(in_r0,0);
    uVar5 = ResumeGenerator(uVar4,1);
    uVar6 = ResumeGenerator(uVar4,2);
    uVar10 = ResumeGenerator(uVar4,3);
    uVar11 = ResumeGenerator(uVar4,4);
    ResumeGenerator(uVar4,5);
    ResumeGenerator(uVar4,6);
    uVar14 = ResumeGenerator(uVar4,7);
    uVar15 = ResumeGenerator(uVar4,8);
    ResumeGenerator(uVar4,9);
    ResumeGenerator(uVar4,10);
    uVar17 = ResumeGenerator(uVar4,0xb);
    uVar18 = ResumeGenerator(uVar4,0xc);
    uVar19 = ResumeGenerator(uVar4,0xd);
    uVar20 = ResumeGenerator(uVar4,0xe);
    uVar21 = ResumeGenerator(uVar4,0xf);
    iVar12 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar4);
    if (iVar12 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    iVar22 = GetIterator(in_acc);
    bVar1 = (boolean)IsJSReceiver(iVar22);
    if (!bVar1) {
      iVar22 = CallRuntime(%ThrowSymbolIteratorInvalid);
    }
    uVar3 = iVar22.next;
    iVar12 = in_acc;
LAB_109681eb:
    iVar23 = true;
    iVar24 = CallProperty(uVar3,iVar22);
    bVar1 = (boolean)IsJSReceiver(iVar24);
    if (!bVar1) {
      CallRuntime(%ThrowIteratorResultNotAnObject,iVar24);
    }
    if (iVar24.done != 0) {
      in_acc = -1;
      uVar2 = 0xffffffff;
      break;
    }
    iVar13 = iVar24.value;
    uVar2 = false;
    uVar16 = Call(_0x33c862,a0,iVar13.name);
    uVar25 = iVar13.isDirectory;
    iVar23 = CallProperty(uVar25,iVar13);
    if (iVar23 == 0) {
      uVar25 = InvokeIntrinsic(%_AsyncGeneratorYield,uVar4,uVar16,false);
      SuspendGenerator(uVar4,uVar4,uVar5,uVar6,uVar10,uVar11,iVar12,iVar13,uVar14,uVar15,iVar13,
                       uVar16,uVar17,uVar18,uVar19,uVar20,uVar21,uVar3,iVar22,uVar2,in_r19,in_r20,
                       in_context,iVar13);
      return uVar25;
    }
    iVar32 = Call(uVar14,uVar16);
    iVar34 = iVar32.name_36;
    if ((iVar34 == undefined) || (iVar34 == null)) {
LAB_109682d8:
      iVar34 = CallProperty(iVar32.name_37,iVar32);
      iVar26 = InvokeIntrinsic(%_CreateAsyncFromSyncIterator,iVar34);
    }
    else {
      iVar26 = CallProperty(iVar34,iVar32);
      bVar1 = (boolean)IsJSReceiver(iVar26);
      if (!bVar1) {
        CallRuntime(%ThrowSymbolAsyncIteratorInvalid);
        goto LAB_109682d8;
      }
    }
    uVar30 = iVar26.next;
    in_acc = undefined;
    uVar9 = 0;
    iVar23 = iVar13;
    iVar24 = iVar13;
    goto LAB_109682f6;
  case 0x10968321:
    uVar4 = ResumeGenerator(in_r0,0);
    ResumeGenerator(uVar4,1);
    ResumeGenerator(uVar4,2);
    ResumeGenerator(uVar4,3);
    ResumeGenerator(uVar4,4);
    ResumeGenerator(uVar4,5);
    ResumeGenerator(uVar4,6);
    ResumeGenerator(uVar4,7);
    ResumeGenerator(uVar4,8);
    ResumeGenerator(uVar4,9);
    ResumeGenerator(uVar4,10);
    ResumeGenerator(uVar4,0xb);
    ResumeGenerator(uVar4,0xc);
    ResumeGenerator(uVar4,0xd);
    ResumeGenerator(uVar4,0xe);
    ResumeGenerator(uVar4,0xf);
    ResumeGenerator(uVar4,0x10);
    iVar22 = ResumeGenerator(uVar4,0x11);
    iVar23 = ResumeGenerator(uVar4,0x12);
    ResumeGenerator(uVar4,0x13);
    ResumeGenerator(uVar4,0x14);
    ResumeGenerator(uVar4,0x15);
    ResumeGenerator(uVar4,0x16);
    ResumeGenerator(uVar4,0x17);
    ResumeGenerator(uVar4,0x18);
    ResumeGenerator(uVar4,0x19);
    ResumeGenerator(uVar4,0x1a);
    ResumeGenerator(uVar4,0x1b);
    iVar12 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar4);
    if (iVar12 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    uVar2 = 1;
    break;
  case 0x10968369:
    uVar4 = ResumeGenerator(in_r0,0);
    uVar5 = ResumeGenerator(uVar4,1);
    uVar6 = ResumeGenerator(uVar4,2);
    uVar10 = ResumeGenerator(uVar4,3);
    uVar11 = ResumeGenerator(uVar4,4);
    iVar12 = ResumeGenerator(uVar4,5);
    iVar13 = ResumeGenerator(uVar4,6);
    uVar14 = ResumeGenerator(uVar4,7);
    uVar15 = ResumeGenerator(uVar4,8);
    iVar23 = ResumeGenerator(uVar4,9);
    uVar16 = ResumeGenerator(uVar4,10);
    uVar17 = ResumeGenerator(uVar4,0xb);
    uVar18 = ResumeGenerator(uVar4,0xc);
    uVar19 = ResumeGenerator(uVar4,0xd);
    uVar20 = ResumeGenerator(uVar4,0xe);
    uVar21 = ResumeGenerator(uVar4,0xf);
    uVar3 = ResumeGenerator(uVar4,0x10);
    iVar22 = ResumeGenerator(uVar4,0x11);
    uVar2 = ResumeGenerator(uVar4,0x12);
    in_r19 = ResumeGenerator(uVar4,0x13);
    in_r20 = ResumeGenerator(uVar4,0x14);
    in_context = ResumeGenerator(uVar4,0x15);
    iVar24 = ResumeGenerator(uVar4,0x16);
    uVar25 = ResumeGenerator(uVar4,0x17);
    uVar9 = ResumeGenerator(uVar4,0x18);
    iVar26 = ResumeGenerator(uVar4,0x19);
    iVar27 = ResumeGenerator(uVar4,0x1a);
    uVar30 = ResumeGenerator(uVar4,0x1b);
    iVar32 = ResumeGenerator(uVar4,0x1c);
    iVar34 = ResumeGenerator(uVar4,0x1d);
    iVar7 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar4);
    if (iVar7 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    bVar1 = (boolean)IsJSReceiver(in_acc);
    if (!bVar1) {
      CallRuntime(%ThrowIteratorResultNotAnObject,in_acc);
    }
    goto LAB_10968388;
  case 0x1096839b:
    uVar4 = ResumeGenerator(in_r0,0);
    uVar5 = ResumeGenerator(uVar4,1);
    uVar6 = ResumeGenerator(uVar4,2);
    uVar10 = ResumeGenerator(uVar4,3);
    uVar11 = ResumeGenerator(uVar4,4);
    iVar12 = ResumeGenerator(uVar4,5);
    uVar2 = ResumeGenerator(uVar4,6);
    uVar14 = ResumeGenerator(uVar4,7);
    uVar15 = ResumeGenerator(uVar4,8);
    uVar16 = ResumeGenerator(uVar4,9);
    uVar25 = ResumeGenerator(uVar4,10);
    uVar17 = ResumeGenerator(uVar4,0xb);
    uVar18 = ResumeGenerator(uVar4,0xc);
    uVar19 = ResumeGenerator(uVar4,0xd);
    uVar20 = ResumeGenerator(uVar4,0xe);
    uVar21 = ResumeGenerator(uVar4,0xf);
    uVar3 = ResumeGenerator(uVar4,0x10);
    iVar22 = ResumeGenerator(uVar4,0x11);
    iVar23 = ResumeGenerator(uVar4,0x12);
    in_r19 = ResumeGenerator(uVar4,0x13);
    in_r20 = ResumeGenerator(uVar4,0x14);
    in_context = ResumeGenerator(uVar4,0x15);
    uVar30 = ResumeGenerator(uVar4,0x16);
    ResumeGenerator(uVar4,0x17);
    iVar13 = ResumeGenerator(uVar4,0x18);
    uVar9 = ResumeGenerator(uVar4,0x19);
    uVar28 = ResumeGenerator(uVar4,0x1a);
    uVar29 = ResumeGenerator(uVar4,0x1b);
    uVar31 = ResumeGenerator(uVar4,0x1c);
    uVar33 = ResumeGenerator(uVar4,0x1d);
    iVar24 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar4);
    if (iVar24 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    bVar1 = (boolean)IsJSReceiver(in_acc);
    if (!bVar1) {
      CallRuntime(%ThrowIteratorResultNotAnObject,in_acc);
    }
    if (in_acc.done == 0) {
      uVar8 = InvokeIntrinsic(%_AsyncGeneratorYield,uVar4,in_acc.value,false);
      SuspendGenerator(uVar4,uVar4,uVar5,uVar6,uVar10,uVar11,iVar12,uVar2,uVar14,uVar15,uVar16,
                       uVar25,uVar17,uVar18,uVar19,uVar20,uVar21,uVar3,iVar22,iVar23,in_r19,in_r20,
                       in_context,uVar30,in_acc,iVar13,uVar9,uVar28,uVar29,uVar31,uVar33,in_acc,0);
      return uVar8;
    }
    in_acc = in_acc.value;
    if (iVar13 != 1) goto LAB_109681eb;
    uVar2 = 1;
    break;
  case 0x109683d6:
    uVar4 = ResumeGenerator(in_r0,0);
    uVar5 = ResumeGenerator(uVar4,1);
    uVar6 = ResumeGenerator(uVar4,2);
    uVar10 = ResumeGenerator(uVar4,3);
    uVar11 = ResumeGenerator(uVar4,4);
    iVar12 = ResumeGenerator(uVar4,5);
    iVar13 = ResumeGenerator(uVar4,6);
    uVar14 = ResumeGenerator(uVar4,7);
    uVar15 = ResumeGenerator(uVar4,8);
    iVar23 = ResumeGenerator(uVar4,9);
    uVar16 = ResumeGenerator(uVar4,10);
    uVar17 = ResumeGenerator(uVar4,0xb);
    uVar18 = ResumeGenerator(uVar4,0xc);
    uVar19 = ResumeGenerator(uVar4,0xd);
    uVar20 = ResumeGenerator(uVar4,0xe);
    uVar21 = ResumeGenerator(uVar4,0xf);
    uVar3 = ResumeGenerator(uVar4,0x10);
    iVar22 = ResumeGenerator(uVar4,0x11);
    uVar2 = ResumeGenerator(uVar4,0x12);
    in_r19 = ResumeGenerator(uVar4,0x13);
    in_r20 = ResumeGenerator(uVar4,0x14);
    in_context = ResumeGenerator(uVar4,0x15);
    iVar24 = ResumeGenerator(uVar4,0x16);
    uVar25 = ResumeGenerator(uVar4,0x17);
    ResumeGenerator(uVar4,0x18);
    iVar26 = ResumeGenerator(uVar4,0x19);
    ResumeGenerator(uVar4,0x1a);
    uVar30 = ResumeGenerator(uVar4,0x1b);
    iVar32 = ResumeGenerator(uVar4,0x1c);
    iVar34 = ResumeGenerator(uVar4,0x1d);
    ResumeGenerator(uVar4,0x1e);
    ResumeGenerator(uVar4,0x1f);
    uVar9 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar4);
LAB_109682f6:
                    /* WARNING: Switch is manually overridden */
    uVar28 = SwitchTarget(uVar9,0x26,2,1);
    switch(uVar28) {
    case 0x109682fc:
      uVar28 = CallProperty(uVar30,iVar26,in_acc);
      break;
    case 0x10968303:
      iVar32 = iVar26.return;
      if ((iVar32 == undefined) || (iVar32 == null)) {
        uVar28 = InvokeIntrinsic(%_AsyncGeneratorAwaitUncaught,uVar4,in_acc);
        SuspendGenerator(uVar4,uVar4,uVar5,uVar6,uVar10,uVar11,iVar12,iVar13,uVar14,uVar15,iVar23,
                         uVar16,uVar17,uVar18,uVar19,uVar20,uVar21,uVar3,iVar22,uVar2,in_r19,in_r20,
                         in_context,iVar24,uVar25,uVar9,iVar26,in_acc,uVar30);
        return uVar28;
      }
      uVar28 = CallProperty(iVar32,iVar26,in_acc);
      break;
    case 0x1096833e:
      iVar27 = iVar26.throw;
      if ((iVar27 == undefined) || (iVar27 == null)) {
        iVar7 = iVar26.return;
        iVar27 = in_acc;
        if ((iVar7 != undefined) && (iVar7 != null)) {
          uVar28 = CallProperty(iVar7,iVar26);
          uVar28 = InvokeIntrinsic(%_AsyncGeneratorAwaitUncaught,uVar4,uVar28);
          SuspendGenerator(uVar4,uVar4,uVar5,uVar6,uVar10,uVar11,iVar12,iVar13,uVar14,uVar15,iVar23,
                           uVar16,uVar17,uVar18,uVar19,uVar20,uVar21,uVar3,iVar22,uVar2,in_r19,
                           in_r20,in_context,iVar24,uVar25,uVar9,iVar26,in_acc,uVar30,iVar32,iVar34)
          ;
          return uVar28;
        }
LAB_10968388:
        uVar28 = CallRuntime(%ThrowThrowMethodMissing);
        in_acc = iVar27;
      }
      else {
        uVar28 = CallProperty(iVar27,iVar26,in_acc);
      }
    }
    uVar28 = InvokeIntrinsic(%_AsyncGeneratorAwaitUncaught,uVar4,uVar28);
    SuspendGenerator(uVar4,uVar4,uVar5,uVar6,uVar10,uVar11,iVar12,iVar13,uVar14,uVar15,iVar23,uVar16
                     ,uVar17,uVar18,uVar19,uVar20,uVar21,uVar3,iVar22,uVar2,in_r19,in_r20,in_context
                     ,iVar24,uVar25,uVar9,iVar26,in_acc,uVar30,iVar32,iVar34);
    return uVar28;
  case 0x10968410:
    uVar4 = ResumeGenerator(in_r0,0);
    uVar5 = ResumeGenerator(uVar4,1);
    uVar6 = ResumeGenerator(uVar4,2);
    uVar10 = ResumeGenerator(uVar4,3);
    uVar11 = ResumeGenerator(uVar4,4);
    iVar12 = ResumeGenerator(uVar4,5);
    ResumeGenerator(uVar4,6);
    uVar14 = ResumeGenerator(uVar4,7);
    uVar15 = ResumeGenerator(uVar4,8);
    ResumeGenerator(uVar4,9);
    ResumeGenerator(uVar4,10);
    uVar17 = ResumeGenerator(uVar4,0xb);
    uVar18 = ResumeGenerator(uVar4,0xc);
    uVar19 = ResumeGenerator(uVar4,0xd);
    uVar20 = ResumeGenerator(uVar4,0xe);
    uVar21 = ResumeGenerator(uVar4,0xf);
    uVar3 = ResumeGenerator(uVar4,0x10);
    iVar22 = ResumeGenerator(uVar4,0x11);
    iVar23 = ResumeGenerator(uVar4,0x12);
    in_r19 = ResumeGenerator(uVar4,0x13);
    in_r20 = ResumeGenerator(uVar4,0x14);
    in_context = ResumeGenerator(uVar4,0x15);
    ResumeGenerator(uVar4,0x16);
    uVar2 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar4);
                    /* WARNING: Switch is manually overridden */
    uVar2 = SwitchTarget(uVar2,0x2b,2,0);
    switch(uVar2) {
    case 0x1096841e:
      Throw(in_acc);
      return in_acc;
    case 0x10968421:
      uVar2 = 1;
      break;
    case 0x1096842a:
      goto LAB_109681eb;
    }
  }
  if (iVar23 == 0) {
    iVar12 = iVar22.return;
    if ((iVar12 != undefined) && (iVar12 != null)) {
      uVar3 = CallProperty(iVar12,iVar22);
      bVar1 = (boolean)IsJSReceiver(uVar3);
      if (!bVar1) {
        CallRuntime(%ThrowIteratorResultNotAnObject,uVar3);
      }
    }
  }
                    /* WARNING: Switch is manually overridden */
  uVar2 = SwitchTarget(uVar2,0x2f,2,0);
  switch(uVar2) {
  case 0x10968474:
    in_acc = undefined;
    break;
  case 0x10968476:
    ReThrow(in_acc);
    return in_acc;
  case 0x10968479:
  }
LAB_109684b2:
  InvokeIntrinsic(%_GeneratorClose,uVar4);
                    /* WARNING: Switch is manually overridden */
  uVar2 = SwitchTarget(1,0x33,3,0);
  switch(uVar2) {
  case 0x109684c3:
    return undefined;
  case 0x109684c5:
    ReThrow(in_acc);
    return in_acc;
  case 0x109684c8:
    uVar2 = InvokeIntrinsic(%_AsyncGeneratorResolve,uVar4,in_acc,true);
    return uVar2;
  case 0x109684d6:
    return in_acc;
  }
}
