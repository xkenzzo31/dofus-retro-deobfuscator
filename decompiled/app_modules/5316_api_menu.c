/* 5316 [lit 304, 3 args] <- anonymous_51 */
undefined4 5316(undefined4 receiver,int a0,undefined4 a1,undefined4 a2)
{
  CreateFunctionContext(scope_5316);
  CreateBlockContext(block_scope_5316);
  iVar2 = Call(a2,0x2518);
  _0x2bb79e = iVar2.BrowserWindow;
  _0x18558f = iVar2.app;
  _0x215631 = iVar2.Menu;
  Call(a2,0x1d66);
  uVar3 = CreateClosure(anonymous_311);
  a0.exports.getMenu = uVar3;
  uVar3 = CreateClosure(anonymous_317);
  a0.exports.getApplicationMenu = uVar3;
  uVar3 = CreateClosure(anonymous_326);
  a0.exports.setApplicationMenu = uVar3;
  iVar2 = CreateArrayLiteral(ArrayBoilerplateDescription);
  iVar4 = CreateObjectLiteral({label, submenu});
  iVar5 = api.i18n;
  uVar3 = CallProperty(iVar5.translate,iVar5,"Menu_View");
  iVar4.label = uVar3;
  uVar3 = CreateArrayLiteral(ArrayBoilerplateDescription);
  iVar5 = CreateObjectLiteral({label, accelerator, click});
  iVar6 = api.i18n;
  uVar7 = CallProperty(iVar6.translate,iVar6,"Menu_Reload");
  iVar5.label = uVar7;
  iVar5.accelerator = "CmdOrCtrl+R";
  uVar7 = CreateClosure(click_332);
  iVar5.click = uVar7;
  SetProperty(uVar3,0,iVar5);
  iVar5 = CreateObjectLiteral({label, accelerator, click});
  iVar6 = api.i18n;
  uVar7 = CallProperty(iVar6.translate,iVar6,"Menu_ToggleFullScreen");
  iVar5.label = uVar7;
  iVar5.accelerator = "CmdOrCtrl+F";
  uVar7 = CreateClosure(click_338);
  iVar5.click = uVar7;
  SetProperty(uVar3,1,iVar5);
  iVar4.submenu = uVar3;
  SetProperty(iVar2,0,iVar4);
  cVar1 = LooseEquals("darwin",process.platform);
  _0x112ffb = iVar2;
  if (cVar1 != '\0') {
    uVar3 = iVar2.unshift;
    iVar4 = CreateObjectLiteral({label, submenu});
    iVar5 = api.i18n;
    uVar7 = CallProperty(iVar5.translate,iVar5,"Menu_Edit");
    iVar4.label = uVar7;
    uVar7 = CreateArrayLiteral(ArrayBoilerplateDescription);
    iVar5 = CreateObjectLiteral({label, role});
    iVar6 = api.i18n;
    uVar8 = CallProperty(iVar6.translate,iVar6,"Menu_Copy");
    iVar5.label = uVar8;
    iVar5.role = "copy";
    SetProperty(uVar7,0,iVar5);
    iVar5 = CreateObjectLiteral({label, role});
    iVar6 = api.i18n;
    uVar8 = CallProperty(iVar6.translate,iVar6,"Menu_Paste");
    iVar5.label = uVar8;
    iVar5.role = "paste";
    SetProperty(uVar7,1,iVar5);
    iVar5 = CreateObjectLiteral({label, role});
    iVar6 = api.i18n;
    uVar8 = CallProperty(iVar6.translate,iVar6,"Menu_SelectAll");
    iVar5.label = uVar8;
    iVar5.role = "selectall";
    SetProperty(uVar7,2,iVar5);
    iVar4.submenu = uVar7;
    CallProperty(uVar3,iVar2,iVar4);
    iVar4 = CallProperty(_0x18558f.getName,_0x18558f);
    iVar5 = CreateEmptyObjectLiteral();
    iVar5.type = "separator";
    iVar6 = CreateEmptyObjectLiteral();
    iVar6.label = "Services";
    iVar6.role = "services";
    uVar3 = CreateEmptyArrayLiteral();
    iVar6.submenu = uVar3;
    iVar9 = CreateEmptyObjectLiteral();
    iVar9.type = "separator";
    iVar10 = CreateEmptyObjectLiteral();
    iVar10.type = "separator";
    iVar2 = _0x112ffb;
    uVar3 = _0x112ffb.unshift;
    iVar11 = CreateObjectLiteral({label, submenu});
    iVar11.label = iVar4;
    uVar7 = CreateArrayLiteral(ArrayBoilerplateDescription);
    iVar12 = CreateObjectLiteral({label, role});
    iVar13 = api.i18n;
    iVar13 = CallProperty(iVar13.translate,iVar13,"Menu_About");
    iVar12.label = " " + iVar4 + iVar13;
    iVar12.role = "about";
    SetProperty(uVar7,0,iVar12);
    SetProperty(uVar7,1,iVar5);
    SetProperty(uVar7,2,iVar6);
    SetProperty(uVar7,3,iVar9);
    iVar5 = CreateObjectLiteral({label, accelerator, role});
    iVar6 = api.i18n;
    iVar6 = CallProperty(iVar6.translate,iVar6,"Menu_Hide");
    iVar5.label = " " + iVar4 + iVar6;
    iVar5.accelerator = "Command+H";
    iVar5.role = "hide";
    SetProperty(uVar7,4,iVar5);
    iVar4 = CreateObjectLiteral({label, accelerator, role});
    iVar5 = api.i18n;
    uVar8 = CallProperty(iVar5.translate,iVar5,"Menu_HideOthers");
    iVar4.label = uVar8;
    iVar4.accelerator = "Command+Alt+H";
    iVar4.role = "hideothers";
    SetProperty(uVar7,5,iVar4);
    iVar4 = CreateObjectLiteral({label, role});
    iVar5 = api.i18n;
    uVar8 = CallProperty(iVar5.translate,iVar5,"Menu_ShowAll");
    iVar4.label = uVar8;
    iVar4.role = "unhide";
    SetProperty(uVar7,6,iVar4);
    SetProperty(uVar7,7,iVar10);
    iVar4 = CreateObjectLiteral({label, accelerator, click});
    iVar5 = api.i18n;
    uVar8 = CallProperty(iVar5.translate,iVar5,"Menu_Quit");
    iVar4.label = uVar8;
    iVar4.accelerator = "Command+Q";
    uVar8 = CreateClosure(click_359);
    iVar4.click = uVar8;
    SetProperty(uVar7,8,iVar4);
    iVar11.submenu = uVar7;
    CallProperty(uVar3,iVar2,iVar11);
  }
  iVar2 = _0x112ffb;
  if (process.defaultApp != 0) {
    uVar3 = _0x112ffb.push;
    iVar4 = CreateObjectLiteral({label, submenu});
    iVar4.label = "Dev";
    uVar7 = CreateArrayLiteral(ArrayBoilerplateDescription);
    iVar5 = CreateObjectLiteral({label, accelerator, click});
    iVar6 = api.i18n;
    uVar8 = CallProperty(iVar6.translate,iVar6,"Menu_ToggleDeveloperTools");
    iVar5.label = uVar8;
    if ("darwin" == process.platform) {
      pcVar14 = "Alt+Command+I";
    }
    else {
      pcVar14 = "Ctrl+Shift+I";
    }
    iVar5.accelerator = pcVar14;
    uVar8 = CreateClosure(click_367);
    iVar5.click = uVar8;
    SetProperty(uVar7,0,iVar5);
    iVar5 = CreateObjectLiteral({label, click});
    iVar5.label = "chrome://gpu";
    uVar8 = CreateClosure(click_373);
    iVar5.click = uVar8;
    SetProperty(uVar7,1,iVar5);
    iVar5 = CreateObjectLiteral({label, click});
    iVar5.label = "Go RetroChat";
    uVar8 = CreateClosure(click_385);
    iVar5.click = uVar8;
    SetProperty(uVar7,2,iVar5);
    iVar5 = CreateObjectLiteral({label, click});
    iVar5.label = "Go RetroConsole";
    uVar8 = CreateClosure(click_391);
    iVar5.click = uVar8;
    SetProperty(uVar7,3,iVar5);
    iVar4.submenu = uVar7;
    CallProperty(uVar3,iVar2,iVar4);
  }
  return undefined;
}
/* anonymous_311 [lit 311, 0 args] <- 5316 */
undefined4 anonymous_311(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_311);
  return _0xa4018;
}
/* anonymous_317 [lit 317, 0 args] <- 5316 */
undefined4 anonymous_317(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_317);
  uVar1 = CallProperty(_0x215631.getApplicationMenu,_0x215631);
  return uVar1;
}
/* anonymous_326 [lit 326, 0 args] <- 5316 */
undefined4 anonymous_326(undefined4 receiver)
{
  CreateFunctionContext(scope_anonymous_326);
  _0xa4018 = CallProperty(_0x215631.buildFromTemplate,_0x215631,_0x112ffb);
  CallProperty(_0x215631.setApplicationMenu,_0x215631,_0xa4018);
  return undefined;
}
/* click_332 [lit 332, 2 args] <- 5316 */
undefined4 click_332(undefined4 receiver,undefined4 a0,int a1)
{
  CreateFunctionContext(scope_click_332);
  if (a1 != 0) {
    CallProperty(a1.reload,a1);
  }
  return undefined;
}
/* click_338 [lit 338, 2 args] <- 5316 */
undefined4 click_338(undefined4 receiver,undefined4 a0,int a1)
{
  CreateFunctionContext(scope_click_338);
  if (a1 != 0) {
    iVar1 = CallProperty(a1.isFullScreen,a1);
    CallProperty(a1.setFullScreen,a1,(int)(iVar1 == 0));
  }
  return undefined;
}
/* click_359 [lit 359, 0 args] <- 5316 */
undefined4 click_359(undefined4 receiver)
{
  CreateFunctionContext(scope_click_359);
  CallProperty(_0x18558f.quit,_0x18558f);
  return undefined;
}
/* click_367 [lit 367, 2 args] <- 5316 */
undefined4 click_367(undefined4 receiver,undefined4 a0,int a1)
{
  CreateFunctionContext(scope_click_367);
  if (a1 != 0) {
    CallProperty(a1.toggleDevTools,a1);
  }
  return undefined;
}
/* click_373 [lit 373, 2 args] <- 5316 */
undefined4 click_373(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_click_373);
  iVar1 = CreateEmptyObjectLiteral();
  iVar1.width = 0x400;
  iVar1.height = 0x300;
  iVar1.useContentSize = true;
  iVar1 = Construct(_0x2bb79e,iVar1);
  CallProperty(iVar1.loadURL,iVar1,"chrome://gpu");
  return undefined;
}
/* click_385 [lit 385, 2 args] <- 5316 */
undefined4 click_385(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_click_385);
  iVar1 = api.game;
  CallProperty(iVar1.retroChatOpen,iVar1);
  return undefined;
}
/* click_391 [lit 391, 2 args] <- 5316 */
undefined4 click_391(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_click_391);
  iVar1 = api.game;
  CallProperty(iVar1.retroConsoleOpen,iVar1);
  return undefined;
}
