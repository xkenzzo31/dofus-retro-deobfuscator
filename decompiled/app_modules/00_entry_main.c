/* anonymous_9065 [lit 9065, 0 args] <- anonymous_51 */
undefined4 anonymous_9065(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_9065);
  iVar1 = Call(_0xd94ba6,0x2518);
  _0x1abaeb = iVar1.app;
  iVar1 = Call(_0xd94ba6,0x2518);
  iVar1 = iVar1.powerSaveBlocker;
  iVar2 = Call(_0xd94ba6,0x1ad3);
  iVar3 = Call(_0xd94ba6,0x3f9);
  _0x4b359c = Call(_0xd94ba6,0x1c96);
  iVar4 = Call(_0xd94ba6,0x2518);
  iVar4 = iVar4.ipcMain;
  iVar5 = Call(_0xd94ba6,0x821);
  _0x2a000f = iVar5.execFile;
  iVar5 = Call(_0xd94ba6,0xf6c);
  CallProperty(iVar5.initialize,iVar5);
  iVar5 = Call(_0xd94ba6,0x1416);
  uVar6 = iVar5.config;
  iVar7 = CreateObjectLiteral({path});
  uVar8 = CallProperty(_0x1abaeb.getPath,_0x1abaeb,"userData");
  uVar8 = CallProperty(iVar3.join,iVar3,uVar8,"RetroModern.env");
  iVar7.path = uVar8;
  CallProperty(uVar6,iVar5,iVar7);
  iVar5 = _0x1abaeb.commandLine;
  CallProperty(iVar5.appendSwitch,iVar5,"disable-features","CalculateNativeWinOcclusion");
  iVar5 = _0x1abaeb.commandLine;
  CallProperty(iVar5.appendSwitch,iVar5,"disable-renderer-backgrounding");
  uVar6 = CreateClosure(anonymous_9071);
  CallProperty(_0x1abaeb.on,_0x1abaeb,"window-all-closed",uVar6);
  uVar6 = CreateClosure(anonymous_9073);
  CallProperty(_0x1abaeb.on,_0x1abaeb,"web-contents-created",uVar6);
  uVar6 = CreateClosure(anonymous_9089);
  CallProperty(_0x1abaeb.on,_0x1abaeb,"ready",uVar6);
  uVar6 = CreateClosure(anonymous_9120);
  CallProperty(process.on,process,"uncaughtException",uVar6);
  CallProperty(_0x4b359c.init,_0x4b359c);
  CallProperty(iVar1.start,iVar1,"prevent-app-suspension");
  iVar1 = _0x1abaeb.commandLine;
  CallProperty(iVar1.appendSwitch,iVar1,"no-sandbox");
  uVar6 = CallProperty(iVar3.join,iVar3,__dirname,"pepperflash");
  if (process.defaultApp == 0) {
    if ("win32" == process.platform) {
      CallProperty(_0x1abaeb.setAppUserModelId,_0x1abaeb,"com.dofus.d1elauncher");
      uVar8 = CallProperty(iVar3.join,iVar3,__dirname,"snoretoast/SnoreToast.exe");
      uVar10 = CreateArrayLiteral(ArrayBoilerplateDescription);
      SetProperty(uVar10,0,"-install");
      SetProperty(uVar10,1,"Dofus Retro/Dofus 1.lnk");
      uVar11 = CallProperty(_0x1abaeb.getPath,_0x1abaeb,"exe");
      SetProperty(uVar10,2,uVar11);
      SetProperty(uVar10,3,"com.dofus.d1elauncher");
      uVar11 = CreateClosure(anonymous_9122);
      Call(_0x2a000f,uVar8,uVar10,uVar11);
    }
  }
  else {
    pcVar9 = process.platform;
    if (pcVar9 == "win32") {
      uVar6 = CallProperty(iVar3.join,iVar3,uVar6,"win");
    }
    else if (pcVar9 == "darwin") {
      uVar6 = CallProperty(iVar3.join,iVar3,uVar6,"mac");
    }
    else if (pcVar9 == "linux") {
      uVar6 = CallProperty(iVar3.join,iVar3,uVar6,"linux");
    }
  }
  CallProperty(iVar2.addSource,iVar2,uVar6);
  CallProperty(iVar2.load,iVar2);
  uVar6 = CreateClosure(anonymous_9126);
  CallProperty(iVar4.on,iVar4,"retroConsoleClear",uVar6);
  uVar6 = CreateClosure(anonymous_9132);
  CallProperty(iVar4.on,iVar4,"retroConsoleAddText",uVar6);
  uVar6 = CreateClosure(anonymous_9138);
  CallProperty(iVar4.on,iVar4,"retroConsoleSetPromptText",uVar6);
  uVar6 = CreateClosure(anonymous_9144);
  CallProperty(iVar4.on,iVar4,"retroConsoleFocusPrompt",uVar6);
  uVar6 = CreateClosure(anonymous_9150);
  CallProperty(iVar4.on,iVar4,"retroConsoleSetHeaderLabel",uVar6);
  uVar6 = CreateClosure(anonymous_9156);
  CallProperty(iVar4.on,iVar4,"retroConsoleHref",uVar6);
  uVar6 = CreateClosure(anonymous_9162);
  CallProperty(iVar4.on,iVar4,"retroConsoleInput",uVar6);
  uVar6 = CreateClosure(anonymous_9168);
  CallProperty(iVar4.on,iVar4,"retroConsoleFunctionKey",uVar6);
  uVar6 = CreateClosure(anonymous_9174);
  CallProperty(iVar4.on,iVar4,"retroChatClear",uVar6);
  uVar6 = CreateClosure(anonymous_9180);
  CallProperty(iVar4.on,iVar4,"retroChatRefresh",uVar6);
  uVar6 = CreateClosure(anonymous_9186);
  CallProperty(iVar4.on,iVar4,"retroChatAddText",uVar6);
  uVar6 = CreateClosure(anonymous_9192);
  CallProperty(iVar4.on,iVar4,"retroChatSetPrefix",uVar6);
  uVar6 = CreateClosure(anonymous_9198);
  CallProperty(iVar4.on,iVar4,"retroChatFocusPrompt",uVar6);
  uVar6 = CreateClosure(anonymous_9204);
  CallProperty(iVar4.on,iVar4,"retroChatSetPromptText",uVar6);
  uVar6 = CreateClosure(anonymous_9210);
  CallProperty(iVar4.on,iVar4,"retroChatInsertPromptText",uVar6);
  uVar6 = CreateClosure(anonymous_9216);
  CallProperty(iVar4.on,iVar4,"retroChatLangKeyAnswer",uVar6);
  uVar6 = CreateClosure(anonymous_9222);
  CallProperty(iVar4.on,iVar4,"retroChatHref",uVar6);
  uVar6 = CreateClosure(anonymous_9228);
  CallProperty(iVar4.on,iVar4,"retroChatAskLangKey",uVar6);
  uVar6 = CreateClosure(anonymous_9234);
  CallProperty(iVar4.on,iVar4,"retroChatInput",uVar6);
  uVar6 = CreateClosure(anonymous_9240);
  CallProperty(iVar4.on,iVar4,"retroChatFunctionKey",uVar6);
  uVar6 = CreateClosure(anonymous_9246);
  CallProperty(iVar4.on,iVar4,"openClientChatPrefixMenu",uVar6);
  uVar6 = CreateClosure(anonymous_9252);
  CallProperty(iVar4.on,iVar4,"retroChatSetFilter",uVar6);
  uVar6 = CreateClosure(anonymous_9258);
  CallProperty(iVar4.on,iVar4,"retroChatOpened",uVar6);
  uVar6 = CreateClosure(anonymous_9264);
  CallProperty(iVar4.on,iVar4,"retroConsoleOpened",uVar6);
  return undefined;
}
/* anonymous_9071 [lit 9071, 0 args] <- anonymous_9065 */
undefined4 anonymous_9071(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_9071);
  CallProperty(_0x1abaeb.quit,_0x1abaeb);
  return undefined;
}
/* anonymous_9073 [lit 9073, 2 args] <- anonymous_9065 */
undefined4 anonymous_9073(undefined4 receiver,undefined4 a0,int a1)
{
  CreateFunctionContext(scope_anonymous_9073);
  uVar1 = CreateClosure(anonymous_9077);
  CallProperty(a1.on,a1,"will-navigate",uVar1);
  uVar1 = CreateClosure(anonymous_9083);
  CallProperty(a1.on,a1,"new-window",uVar1);
  return undefined;
}
/* anonymous_9077 [lit 9077, 2 args] <- anonymous_9073 */
undefined4 anonymous_9077(undefined4 receiver,int a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9077);
  CallProperty(a0.preventDefault,a0);
  iVar1 = api.utils;
  CallProperty(iVar1.openUrlExternal,iVar1,a1);
  return undefined;
}
/* anonymous_9083 [lit 9083, 2 args] <- anonymous_9073 */
undefined4 anonymous_9083(undefined4 receiver,int a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9083);
  CallProperty(a0.preventDefault,a0);
  iVar1 = api.utils;
  CallProperty(iVar1.openUrlExternal,iVar1,a1);
  return undefined;
}
/* anonymous_9089 [lit 9089, 0 args] <- anonymous_9065 */
undefined4 anonymous_9089(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_9089);
  uVar1 = CreateClosure(anonymous_9095);
  Call(uVar1);
  CallProperty(_0x4b359c.initOnReady,_0x4b359c);
  iVar2 = api.zaap;
  CallProperty(iVar2.initConnect,iVar2);
  iVar2 = api.game;
  CallProperty(iVar2.init,iVar2);
  return undefined;
}
/* anonymous_9095 [lit 9095, 0 args] <- anonymous_9089 */
undefined4 anonymous_9095(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_9095);
  _0x41af20 = the_hole;
  if ("darwin" != process.platform) {
    return undefined;
  }
  iVar1 = Call(_0xd94ba6,0x7f5);
  iVar1 = CallProperty(iVar1.release,iVar1);
  uVar2 = CallProperty(iVar1.split,iVar1,".");
  uVar2 = GetProperty(uVar2,0);
  iVar1 = Call(parseInt,uVar2,10);
  if (iVar1 < 0x19) {
    return undefined;
  }
  _0x41af20 = false;
  CreateBlockContext(block_scope_anonymous_9095);
  _0x38f5d1 = "/usr/bin/defaults";
  _0x2113b6 = CreateArrayLiteral(ArrayBoilerplateDescription);
  SetProperty(_0x2113b6,0,"write");
  SetProperty(_0x2113b6,2,"NSAutoFillHeuristicControllerEnabled");
  SetProperty(_0x2113b6,3,"-bool");
  SetProperty(_0x2113b6,4,"false");
  _0x27e4ef = CreateArrayLiteral(ArrayBoilerplateDescription);
  SetProperty(_0x27e4ef,0,"write");
  SetProperty(_0x27e4ef,2,"NSAutoFillHeuristicControllerEnabled");
  SetProperty(_0x27e4ef,3,"-bool");
  SetProperty(_0x27e4ef,4,"true");
  iVar1 = CreateEmptyObjectLiteral();
  iVar1.timeout = 2000;
  uVar2 = CreateArrayLiteral(ArrayBoilerplateDescription);
  SetProperty(uVar2,0,"read");
  SetProperty(uVar2,2,"NSAutoFillHeuristicControllerEnabled");
  uVar3 = CreateClosure(anonymous_9101);
  Call(_0x2a000f,_0x38f5d1,uVar2,iVar1,uVar3);
  uVar2 = CreateClosure(_0x2860ff);
  CallProperty(_0x1abaeb.on,_0x1abaeb,"before-quit",uVar2);
  CallProperty(_0x1abaeb.on,_0x1abaeb,"will-quit",uVar2);
  return undefined;
}
/* anonymous_9101 [lit 9101, 2 args] <- anonymous_9095 */
undefined4 anonymous_9101(undefined4 receiver,int a0,char[] a1)
{
  boolean bVar1;
  CreateFunctionContext(scope_anonymous_9101);
  if (a0 == 0) {
    if (a1 == null) {
      a1 = "";
    }
    iVar3 = CallProperty(a1.trim,a1);
    pcVar2 = CallProperty(iVar3.toLowerCase,iVar3);
    bVar1 = "0" == pcVar2;
    if (!bVar1) {
      bVar1 = "false" == pcVar2;
    }
    _0x41af20 = (int)bVar1;
  }
  else {
    _0x41af20 = false;
  }
  iVar3 = CreateEmptyObjectLiteral();
  iVar3.timeout = 2000;
  if (_0x41af20 == 0) {
    uVar4 = CreateClosure(anonymous_9106);
    Call(_0x2a000f,_0x38f5d1,_0x2113b6,iVar3,uVar4);
  }
  return undefined;
}
/* anonymous_9106 [lit 9106, 1 args] <- anonymous_9101 */
undefined4 anonymous_9106(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_9106);
  if (a0 != 0) {
    iVar1 = a0.message;
    if (iVar1 == 0) {
      iVar1 = a0;
    }
    CallProperty(console.warn,console,"[macOS] Échec désactivation autofill:",iVar1);
  }
  return undefined;
}
/* _0x2860ff [lit 9112, 0 args] <- anonymous_9095 */
undefined4 _0x2860ff(undefined4 receiver)
{
  CreateFunctionContext(scope__0x2860ff);
  iVar1 = CreateEmptyObjectLiteral();
  iVar1.timeout = 2000;
  if (_0x41af20 == 0) {
    uVar2 = CreateClosure(anonymous_9114);
    Call(_0x2a000f,_0x38f5d1,_0x27e4ef,iVar1,uVar2);
  }
  return undefined;
}
/* anonymous_9114 [lit 9114, 1 args] <- _0x2860ff */
undefined4 anonymous_9114(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_9114);
  if (a0 != 0) {
    iVar1 = a0.message;
    if (iVar1 == 0) {
      iVar1 = a0;
    }
    CallProperty(console.warn,console,"[macOS] Impossible de restaurer autofill:",iVar1);
  }
  return undefined;
}
/* anonymous_9120 [lit 9120, 1 args] <- anonymous_9065 */
undefined4 anonymous_9120(undefined4 receiver,undefined4 a0)
{
  CreateFunctionContext(scope_anonymous_9120);
  CallProperty(console.error,console,a0);
  return undefined;
}
/* anonymous_9122 [lit 9122, 2 args] <- anonymous_9065 */
undefined4 anonymous_9122(undefined4 receiver,undefined4 a0,int a1)
{
  CreateFunctionContext(scope_anonymous_9122);
  CallProperty(console.log,console,a0);
  uVar1 = CallProperty(a1.toString,a1);
  CallProperty(console.log,console,uVar1);
  return undefined;
}
/* anonymous_9126 [lit 9126, 2 args] <- anonymous_9065 */
undefined4 anonymous_9126(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9126);
  cVar1 = IsUndetectable(api.consoleWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.consoleWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.consoleWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroConsoleClear");
  }
  return undefined;
}
/* anonymous_9132 [lit 9132, 2 args] <- anonymous_9065 */
undefined4 anonymous_9132(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9132);
  cVar1 = IsUndetectable(api.consoleWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.consoleWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.consoleWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroConsoleAddText",a1);
  }
  return undefined;
}
/* anonymous_9138 [lit 9138, 2 args] <- anonymous_9065 */
undefined4 anonymous_9138(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9138);
  cVar1 = IsUndetectable(api.consoleWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.consoleWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.consoleWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroConsoleSetPromptText",a1);
  }
  return undefined;
}
/* anonymous_9144 [lit 9144, 2 args] <- anonymous_9065 */
undefined4 anonymous_9144(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9144);
  cVar1 = IsUndetectable(api.consoleWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.consoleWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.consoleWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroConsoleFocusPrompt",a1);
  }
  return undefined;
}
/* anonymous_9150 [lit 9150, 2 args] <- anonymous_9065 */
undefined4 anonymous_9150(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9150);
  cVar1 = IsUndetectable(api.consoleWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.consoleWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.consoleWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroConsoleSetHeaderLabel",a1);
  }
  return undefined;
}
/* anonymous_9156 [lit 9156, 2 args] <- anonymous_9065 */
undefined4 anonymous_9156(undefined4 receiver,undefined4 a0,int a1)
{
  CreateFunctionContext(scope_anonymous_9156);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    uVar3 = CallProperty(a1.split,a1,",");
    uVar3 = GetProperty(uVar3,0);
    cVar1 = LooseEquals("ShowPlayerPopupMenu",uVar3);
    if (cVar1 != '\0') {
      iVar2 = api.gameWindow;
      CallProperty(iVar2.focus,iVar2);
      iVar2 = api.gameWindow.webContents;
      CallProperty(iVar2.send,iVar2,"flashGameFocus");
    }
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroConsoleHref",a1);
  }
  return undefined;
}
/* anonymous_9162 [lit 9162, 2 args] <- anonymous_9065 */
undefined4 anonymous_9162(undefined4 receiver,undefined4 a0,int a1)
{
  CreateFunctionContext(scope_anonymous_9162);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = CallProperty(a1.startsWith,a1,"/adminselect");
    if (iVar2 != 0) {
      iVar2 = api.gameWindow;
      CallProperty(iVar2.focus,iVar2);
      iVar2 = api.gameWindow.webContents;
      CallProperty(iVar2.send,iVar2,"flashGameFocus");
    }
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroConsoleInput",a1);
  }
  return undefined;
}
/* _0x3002d1 [lit 9163, 5 args] <- anonymous_9162 */
undefined4 _0x3002d1(undefined4 receiver,undefined4 a0,undefined4 a1,int a2,int a3,int a4)
{
  uVar1 = Call(_0x1b84f0,a4,a2 + 2,a2 - a0_0x2ef225._0x4a5b93,a3 - a0_0x2ef225._0x56e1e5,a4 + -0x10a
  return uVar1;
}
/* anonymous_9168 [lit 9168, 2 args] <- anonymous_9065 */
undefined4 anonymous_9168(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9168);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroConsoleFunctionKey",a1);
  }
  return undefined;
}
/* anonymous_9174 [lit 9174, 2 args] <- anonymous_9065 */
undefined4 anonymous_9174(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9174);
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatClear");
  }
  return undefined;
}
/* anonymous_9180 [lit 9180, 2 args] <- anonymous_9065 */
undefined4 anonymous_9180(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9180);
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatRefresh",a1);
  }
  return undefined;
}
/* _0x18d6c1 [lit 9185, 5 args] <- anonymous_9180 */
undefined4 _0x18d6c1(undefined4 receiver,undefined4 a0,int a1,int a2,int a3,int a4)
{
  uVar1 = Call(_0x44cc86,a0,a1 + 0x11a,a2 - a0_0x578e8b._0x3809d3,a3 - a0_0x578e8b._0x2880cf,a4 + -7
  return uVar1;
}
/* anonymous_9186 [lit 9186, 2 args] <- anonymous_9065 */
undefined4 anonymous_9186(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9186);
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatAddText",a1);
  }
  return undefined;
}
/* anonymous_9192 [lit 9192, 2 args] <- anonymous_9065 */
undefined4 anonymous_9192(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9192);
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatSetPrefix",a1);
  }
  return undefined;
}
/* anonymous_9198 [lit 9198, 2 args] <- anonymous_9065 */
undefined4 anonymous_9198(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9198);
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatFocusPrompt",a1);
  }
  return undefined;
}
/* anonymous_9204 [lit 9204, 2 args] <- anonymous_9065 */
undefined4 anonymous_9204(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9204);
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatSetPromptText",a1);
  }
  return undefined;
}
/* anonymous_9210 [lit 9210, 2 args] <- anonymous_9065 */
undefined4 anonymous_9210(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9210);
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatInsertPromptText",a1);
  }
  return undefined;
}
/* anonymous_9216 [lit 9216, 2 args] <- anonymous_9065 */
undefined4 anonymous_9216(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  cVar1 = IsUndetectable(api.chatWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.chatWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.chatWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatLangKeyAnswer",a1);
  }
  return undefined;
}
/* _0x2e79d7 [lit 9220, 5 args] <- anonymous_9216 */
undefined4 _0x2e79d7(undefined4 receiver,int a0,undefined4 a1,int a2,int a3,int a4)
{
  uVar1 = Call(_0x44cc86,a3,a0 + a0_0x407c0e._0xd0bdb1,a2 + -8,a3 - a0_0x407c0e._0x3120e2,a4 + -0x83
  return uVar1;
}
/* anonymous_9222 [lit 9222, 2 args] <- anonymous_9065 */
undefined4 anonymous_9222(undefined4 receiver,undefined4 a0,int a1)
{
  CreateFunctionContext(scope_anonymous_9222);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    uVar3 = CallProperty(a1.split,a1,",");
    uVar3 = GetProperty(uVar3,0);
    cVar1 = LooseEquals("ShowPlayerPopupMenu",uVar3);
    if (cVar1 != '\0') {
      iVar2 = api.gameWindow;
      CallProperty(iVar2.focus,iVar2);
      iVar2 = api.gameWindow.webContents;
      CallProperty(iVar2.send,iVar2,"flashGameFocus");
    }
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatHref",a1);
  }
  return undefined;
}
/* anonymous_9228 [lit 9228, 2 args] <- anonymous_9065 */
undefined4 anonymous_9228(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9228);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatAskLangKey",a1);
  }
  return undefined;
}
/* anonymous_9234 [lit 9234, 2 args] <- anonymous_9065 */
undefined4 anonymous_9234(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9234);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatInput",a1);
  }
  return undefined;
}
/* anonymous_9240 [lit 9240, 2 args] <- anonymous_9065 */
undefined4 anonymous_9240(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9240);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatFunctionKey",a1);
  }
  return undefined;
}
/* anonymous_9246 [lit 9246, 2 args] <- anonymous_9065 */
undefined4 anonymous_9246(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9246);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"openClientChatPrefixMenu",a1);
  }
  return undefined;
}
/* anonymous_9252 [lit 9252, 2 args] <- anonymous_9065 */
undefined4 anonymous_9252(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9252);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatSetFilter",a1);
  }
  return undefined;
}
/* anonymous_9258 [lit 9258, 2 args] <- anonymous_9065 */
undefined4 anonymous_9258(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9258);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroChatOpened",a1);
  }
  return undefined;
}
/* anonymous_9264 [lit 9264, 2 args] <- anonymous_9065 */
undefined4 anonymous_9264(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_9264);
  cVar1 = IsUndetectable(api.gameWindow);
  if ((cVar1 == '\0') &&
     (iVar2 = api.gameWindow, iVar2 = CallProperty(iVar2.isDestroyed,iVar2), iVar2 == 0)) {
    iVar2 = api.gameWindow.webContents;
    CallProperty(iVar2.send,iVar2,"retroConsoleOpened",a1);
  }
  return undefined;
}
