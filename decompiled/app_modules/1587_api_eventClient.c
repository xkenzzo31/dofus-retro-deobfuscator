/* 1587 [lit 77, 1 args] <- anonymous_51 */
undefined4 1587(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_1587);
  CreateBlockContext(block_scope_1587);
  _0x1f11b9 = 0;
  _0x49b696 = false;
  _0x5e2f92 = Construct(Map);
  uVar1 = CreateClosure(anonymous_89);
  a0.exports.hasEventToSend = uVar1;
  uVar1 = CreateClosure(anonymous_95);
  a0.exports.onReset = uVar1;
  uVar1 = CreateClosure(anonymous_99);
  a0.exports.onMapLoaded = uVar1;
  uVar1 = CreateClosure(anonymous_112);
  a0.exports.onUIOpened = uVar1;
  uVar1 = CreateClosure(anonymous_118);
  a0.exports.onFlush = uVar1;
  a0.exports.flushUICount = _0x4769bc;
  return undefined;
}
/* _0x4769bc [lit 83, 0 args] <- 1587 */
undefined4 _0x4769bc(undefined4 receiver)
{
  uVar2 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
  cVar1 = LooseEquals(0,_0x5e2f92.size);
  if (cVar1 == '\0') {
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"stats_click");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar4 = CallProperty(_0x5e2f92.get,_0x5e2f92,"stats_click");
    }
    else {
      iVar4 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"stats_shortcut");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar5 = CallProperty(_0x5e2f92.get,_0x5e2f92,"stats_shortcut");
    }
    else {
      iVar5 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"spell_click");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar6 = CallProperty(_0x5e2f92.get,_0x5e2f92,"spell_click");
    }
    else {
      iVar6 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"spell_shortcut");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar7 = CallProperty(_0x5e2f92.get,_0x5e2f92,"spell_shortcut");
    }
    else {
      iVar7 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"inventory_click");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar8 = CallProperty(_0x5e2f92.get,_0x5e2f92,"inventory_click");
    }
    else {
      iVar8 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"inventory_shortcut");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar9 = CallProperty(_0x5e2f92.get,_0x5e2f92,"inventory_shortcut");
    }
    else {
      iVar9 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"quest_click");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar10 = CallProperty(_0x5e2f92.get,_0x5e2f92,"quest_click");
    }
    else {
      iVar10 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"quest_shortcut");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar11 = CallProperty(_0x5e2f92.get,_0x5e2f92,"quest_shortcut");
    }
    else {
      iVar11 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"map_click");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar12 = CallProperty(_0x5e2f92.get,_0x5e2f92,"map_click");
    }
    else {
      iVar12 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"map_shortcut");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar13 = CallProperty(_0x5e2f92.get,_0x5e2f92,"map_shortcut");
    }
    else {
      iVar13 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"friend_click");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar14 = CallProperty(_0x5e2f92.get,_0x5e2f92,"friend_click");
    }
    else {
      iVar14 = 0;
    }
    uVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,"friend_shortcut");
    cVar1 = IsUndetectable(uVar3);
    if (cVar1 == '\0') {
      iVar15 = CallProperty(_0x5e2f92.get,_0x5e2f92,"friend_shortcut");
    }
    else {
      iVar15 = 0;
    }
    _0x5e2f92 = Construct(Map);
    iVar16 = api.gameWindow.webContents;
    CallProperty(iVar16.send,iVar16,"onEventClient",
                 "EV2;" + iVar4 + "," + iVar5 + "," + iVar6 + "," + iVar7 + "," + iVar8 +
                 "," + iVar9 + "," + iVar10 + "," + iVar11 + "," + iVar12 + "," + iVar13 +
                 "," + iVar14 + "," + iVar15);
  }
  uVar2 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar2,undefined,false);
  return uVar2;
}
/* anonymous_89 [lit 89, 0 args] <- 1587 */
int anonymous_89(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_89);
  cVar1 = LooseEquals(0,_0x5e2f92.size);
  return (int)(cVar1 == '\0');
}
/* anonymous_95 [lit 95, 0 args] <- 1587 */
undefined4 anonymous_95(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_95);
  uVar1 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
  _0x1f11b9 = 0;
  _0x49b696 = false;
  _0x5e2f92 = Construct(Map);
  uVar1 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar1,undefined,false);
  return uVar1;
}
/* anonymous_99 [lit 99, 0 args] <- 1587 */
undefined4 anonymous_99(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_99);
  uVar2 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
  if (_0x49b696 == 0) {
    _0x1f11b9 = _0x1f11b9 + 1;
    cVar1 = LooseEquals(5,_0x1f11b9);
    if (cVar1 != '\0') {
      _0x49b696 = true;
      iVar3 = api.gameWindow.webContents;
      CallProperty(iVar3.send,iVar3,"onEventClient","EV1");
    }
  }
  uVar2 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar2,undefined,false);
  return uVar2;
}
/* anonymous_112 [lit 112, 1 args] <- 1587 */
undefined4 anonymous_112(undefined4 receiver,undefined4 a0)
{
  CreateFunctionContext(scope_anonymous_112);
  uVar2 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
  iVar3 = CallProperty(_0x5e2f92.get,_0x5e2f92,a0);
  cVar1 = IsUndetectable(iVar3);
  if (cVar1 != '\0') {
    iVar3 = 0;
  }
  CallProperty(_0x5e2f92.set,_0x5e2f92,a0,iVar3 + 1);
  uVar2 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar2,undefined,false);
  return uVar2;
}
/* _0x436777 [lit 115, 5 args] <- anonymous_112 */
undefined4 _0x436777(undefined4 receiver,int a0,int a1,int a2,undefined4 a3,int a4)
{
  uVar1 = Call(_0x4ca1e5,a0 + -1,a1 - a0_0x3abdcf._0x473a66,a2 - a0_0x3abdcf._0x477aea,a3,a4 + -0xd7
  return uVar1;
}
/* anonymous_118 [lit 118, 1 args] <- 1587 */
undefined4 anonymous_118(undefined4 receiver,undefined4 a0)
{
  CreateFunctionContext(scope_anonymous_118);
  uVar1 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
  iVar2 = api.gameWindow.webContents;
  CallProperty(iVar2.send,iVar2,"setWaitingClose",a0);
  Call(_0x4769bc);
  uVar1 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar1,undefined,false);
  return uVar1;
}
