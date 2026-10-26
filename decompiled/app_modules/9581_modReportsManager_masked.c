/* 9581 [lit 397, 3 args] <- anonymous_51 */
undefined4 9581(undefined4 receiver,int a0,undefined4 a1,undefined4 a2)
{
  CreateFunctionContext(scope_9581);
  CreateBlockContext(block_scope_9581);
  iVar1 = Call(a2,0x480);
  _0x2e94ba = iVar1.createReport;
  _0x22b0fb = Call(a2,0x1beb);
  iVar1 = Call(a2,0x2518);
  _0x28cd34 = iVar1.app;
  _0x46cc0e = Call(a2,0x3f9);
  _0x5becf3 = "|/|";
  _0x12435a = Call(a2,0x1440);
  iVar1 = Call(a2,0x2709);
  _0x1d14a2 = iVar1.google.auth.OAuth2;
  _0x538aa9 = Call(a2,0x1611);
  _0x4f6943 = 0;
  uVar2 = CreateClosure(anonymous_445);
  a0.exports.mergeDayReportsDocs = uVar2;
  uVar2 = CreateClosure(anonymous_457);
  a0.exports.printPendingReports = uVar2;
  uVar2 = CreateClosure(anonymous_470);
  a0.exports.sendReports = uVar2;
  uVar2 = CreateClosure(anonymous_518);
  a0.exports.makeReport = uVar2;
  return undefined;
}
/* _0x36384b [lit 409, 1 args] <- 9581 */
undefined4 _0x36384b(undefined4 receiver,int a0)
{
  boolean bVar2;
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar3 = CreateFunctionContext(scope__0x36384b);
    uVar4 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
    uVar5 = CreateClosure(_0x194319);
    uVar6 = CreateClosure(_0x4d7d8f);
    cVar1 = IsUndetectable(a0);
    if (cVar1 != '\0') {
      iVar7 = api.utils;
      a0 = CallProperty(iVar7.getCurrentDate,iVar7);
    }
    uVar8 = CallProperty(_0x28cd34.getPath,_0x28cd34,"userData");
    uVar8 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar8,"RetroReports");
    uVar9 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar8,a0);
    iVar7 = _0x22b0fb.promises;
    uVar10 = CallProperty(iVar7.opendir,iVar7,uVar9);
    uVar10 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar4,uVar10);
    SuspendGenerator(uVar4,uVar4,uVar5,uVar6,in_r3,uVar8,uVar9,in_r6,in_r7,in_r8,in_r9,in_r10,in_r11
                     ,in_r12,in_r13,in_r14,in_r15,in_r16,in_r17,in_r18,in_r19,in_r20,in_r21,in_r22,
                     in_r23,in_r24,in_r25,in_r26,in_r27,in_context,uVar3,uVar3);
    return uVar10;
  }
  uVar3 = GeneratorResumeTarget(in_r0,0,7);
  switch(uVar3) {
  case 0x1011e4bf:
    uVar3 = ResumeGenerator(in_r0,0);
    uVar8 = ResumeGenerator(uVar3,1);
    uVar9 = ResumeGenerator(uVar3,2);
    ResumeGenerator(uVar3,3);
    uVar10 = ResumeGenerator(uVar3,4);
    uVar18 = ResumeGenerator(uVar3,5);
    ResumeGenerator(uVar3,6);
    ResumeGenerator(uVar3,7);
    uVar19 = ResumeGenerator(uVar3,8);
    uVar20 = ResumeGenerator(uVar3,9);
    uVar21 = ResumeGenerator(uVar3,10);
    iVar22 = ResumeGenerator(uVar3,0xb);
    uVar23 = ResumeGenerator(uVar3,0xc);
    uVar24 = ResumeGenerator(uVar3,0xd);
    iVar25 = ResumeGenerator(uVar3,0xe);
    uVar26 = ResumeGenerator(uVar3,0xf);
    uVar27 = ResumeGenerator(uVar3,0x10);
    uVar28 = ResumeGenerator(uVar3,0x11);
    uVar29 = ResumeGenerator(uVar3,0x12);
    uVar30 = ResumeGenerator(uVar3,0x13);
    uVar31 = ResumeGenerator(uVar3,0x14);
    uVar32 = ResumeGenerator(uVar3,0x15);
    uVar33 = ResumeGenerator(uVar3,0x16);
    uVar34 = ResumeGenerator(uVar3,0x17);
    uVar35 = ResumeGenerator(uVar3,0x18);
    uVar36 = ResumeGenerator(uVar3,0x19);
    uVar37 = ResumeGenerator(uVar3,0x1a);
    uVar38 = ResumeGenerator(uVar3,0x1b);
    uVar39 = ResumeGenerator(uVar3,0x1c);
    uVar41 = ResumeGenerator(uVar3,0x1d);
    ResumeGenerator(uVar3,0x1e);
    iVar7 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar7 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    pcVar11 = "";
    iVar7 = 0;
    iVar12 = in_acc.name_166;
    if ((iVar12 == undefined) || (iVar12 == null)) {
LAB_1011f1a1:
      iVar12 = CallProperty(in_acc.name_167,in_acc);
      iVar13 = InvokeIntrinsic(%_CreateAsyncFromSyncIterator,iVar12);
    }
    else {
      iVar13 = CallProperty(iVar12,in_acc);
      bVar2 = (boolean)IsJSReceiver(iVar13);
      if (!bVar2) {
        CallRuntime(%ThrowSymbolAsyncIteratorInvalid);
        goto LAB_1011f1a1;
      }
    }
    uVar6 = iVar13.next;
    iVar17 = in_acc;
    uVar4 = in_context;
    break;
  case 0x1011f1e4:
    uVar3 = ResumeGenerator(in_r0,0);
    uVar8 = ResumeGenerator(uVar3,1);
    uVar9 = ResumeGenerator(uVar3,2);
    iVar17 = ResumeGenerator(uVar3,3);
    uVar10 = ResumeGenerator(uVar3,4);
    uVar18 = ResumeGenerator(uVar3,5);
    pcVar11 = ResumeGenerator(uVar3,6);
    iVar7 = ResumeGenerator(uVar3,7);
    uVar19 = ResumeGenerator(uVar3,8);
    uVar20 = ResumeGenerator(uVar3,9);
    uVar21 = ResumeGenerator(uVar3,10);
    uVar40 = ResumeGenerator(uVar3,0xb);
    uVar23 = ResumeGenerator(uVar3,0xc);
    uVar24 = ResumeGenerator(uVar3,0xd);
    uVar42 = ResumeGenerator(uVar3,0xe);
    uVar26 = ResumeGenerator(uVar3,0xf);
    uVar27 = ResumeGenerator(uVar3,0x10);
    uVar28 = ResumeGenerator(uVar3,0x11);
    uVar29 = ResumeGenerator(uVar3,0x12);
    uVar30 = ResumeGenerator(uVar3,0x13);
    uVar31 = ResumeGenerator(uVar3,0x14);
    uVar32 = ResumeGenerator(uVar3,0x15);
    uVar33 = ResumeGenerator(uVar3,0x16);
    uVar34 = ResumeGenerator(uVar3,0x17);
    uVar35 = ResumeGenerator(uVar3,0x18);
    uVar36 = ResumeGenerator(uVar3,0x19);
    uVar37 = ResumeGenerator(uVar3,0x1a);
    uVar38 = ResumeGenerator(uVar3,0x1b);
    uVar39 = ResumeGenerator(uVar3,0x1c);
    uVar41 = ResumeGenerator(uVar3,0x1d);
    uVar6 = ResumeGenerator(uVar3,0x1e);
    iVar13 = ResumeGenerator(uVar3,0x1f);
    iVar22 = ResumeGenerator(uVar3,0x20);
    iVar12 = ResumeGenerator(uVar3,0x21);
    in_r34 = ResumeGenerator(uVar3,0x22);
    uVar4 = ResumeGenerator(uVar3,0x23);
    ResumeGenerator(uVar3,0x24);
    iVar25 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar25 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    bVar2 = (boolean)IsJSReceiver(in_acc);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,in_acc);
    }
    if (in_acc.done != 0) {
      uVar5 = 0xffffffff;
      uVar4 = 0xffffffff;
      if (iVar22 == 0) {
        iVar25 = iVar13.return;
        if ((iVar25 != undefined) && (iVar25 != null)) {
          uVar4 = CallProperty(iVar25,iVar13);
          uVar4 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar3,uVar4);
          SuspendGenerator(uVar3,uVar3,uVar8,uVar9,iVar17,uVar10,uVar18,pcVar11,iVar7,uVar19,uVar20,
                           uVar21,uVar40,uVar23,uVar24,uVar42,uVar26,uVar27,uVar28,uVar29,uVar30,
                           uVar31,uVar32,uVar33,uVar34,uVar35,uVar36,uVar37,uVar38,uVar39,uVar41,
                           uVar6,iVar13,0,0xffffffff,0xffffffff,in_pending_message,in_acc,in_acc,0,
                           in_context,iVar25);
          return uVar4;
        }
      }
      goto LAB_101216df;
    }
    iVar22 = in_acc.value;
    iVar25 = iVar22.name;
    iVar16 = CallProperty(iVar25.startsWith,iVar25,"~");
    iVar25 = iVar22;
    in_r36 = iVar22;
    if (iVar16 == 0) {
      iVar16 = iVar22.name;
      iVar16 = CallProperty(iVar16.split,iVar16,".");
      uVar5 = CallProperty(iVar16.pop,iVar16);
      cVar1 = LooseEquals("docx",uVar5);
      if (cVar1 != '\0') {
        uVar5 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar18,iVar22.name);
        iVar25 = CreateEmptyObjectLiteral();
        iVar25.path = uVar5;
        uVar19 = CallProperty(_0x538aa9.convertToHtml,_0x538aa9,iVar25);
        uVar19 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar3,uVar19);
        SuspendGenerator(uVar3,uVar3,uVar8,uVar9,iVar17,uVar10,uVar18,pcVar11,iVar7,uVar5,uVar20,
                         uVar21,iVar22,uVar23,uVar24,iVar22,iVar25,uVar27,uVar28,uVar29,uVar30,
                         uVar31,uVar32,uVar33,uVar34,uVar35,uVar36,uVar37,uVar38,uVar39,uVar41,uVar6
                         ,iVar13,false,iVar12,in_r34,uVar4,iVar22,in_acc,0,pcVar11);
        return uVar19;
      }
    }
    break;
  case 0x1011f76f:
    uVar3 = ResumeGenerator(in_r0,0);
    uVar4 = ResumeGenerator(uVar3,1);
    uVar5 = ResumeGenerator(uVar3,2);
    uVar6 = ResumeGenerator(uVar3,3);
    uVar8 = ResumeGenerator(uVar3,4);
    uVar9 = ResumeGenerator(uVar3,5);
    ResumeGenerator(uVar3,6);
    uVar10 = ResumeGenerator(uVar3,7);
    uVar18 = ResumeGenerator(uVar3,8);
    ResumeGenerator(uVar3,9);
    uVar19 = ResumeGenerator(uVar3,10);
    uVar20 = ResumeGenerator(uVar3,0xb);
    uVar21 = ResumeGenerator(uVar3,0xc);
    uVar23 = ResumeGenerator(uVar3,0xd);
    uVar24 = ResumeGenerator(uVar3,0xe);
    uVar26 = ResumeGenerator(uVar3,0xf);
    uVar27 = ResumeGenerator(uVar3,0x10);
    uVar28 = ResumeGenerator(uVar3,0x11);
    uVar29 = ResumeGenerator(uVar3,0x12);
    uVar30 = ResumeGenerator(uVar3,0x13);
    uVar31 = ResumeGenerator(uVar3,0x14);
    uVar32 = ResumeGenerator(uVar3,0x15);
    uVar33 = ResumeGenerator(uVar3,0x16);
    uVar34 = ResumeGenerator(uVar3,0x17);
    uVar35 = ResumeGenerator(uVar3,0x18);
    uVar36 = ResumeGenerator(uVar3,0x19);
    uVar37 = ResumeGenerator(uVar3,0x1a);
    uVar38 = ResumeGenerator(uVar3,0x1b);
    uVar39 = ResumeGenerator(uVar3,0x1c);
    uVar41 = ResumeGenerator(uVar3,0x1d);
    uVar40 = ResumeGenerator(uVar3,0x1e);
    uVar42 = ResumeGenerator(uVar3,0x1f);
    uVar43 = ResumeGenerator(uVar3,0x20);
    uVar44 = ResumeGenerator(uVar3,0x21);
    uVar45 = ResumeGenerator(uVar3,0x22);
    uVar46 = ResumeGenerator(uVar3,0x23);
    uVar47 = ResumeGenerator(uVar3,0x24);
    uVar48 = ResumeGenerator(uVar3,0x25);
    uVar49 = ResumeGenerator(uVar3,0x26);
    iVar17 = ResumeGenerator(uVar3,0x27);
    iVar7 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar7 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    uVar50 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar8,"backup");
    iVar7 = _0x22b0fb.promises;
    uVar15 = CreateEmptyObjectLiteral();
    uVar15 = CallProperty(iVar7.mkdir,iVar7,uVar50,uVar15);
    uVar15 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar3,uVar15);
    SuspendGenerator(uVar3,uVar3,uVar4,uVar5,uVar6,uVar8,uVar9,iVar17 + in_acc.value,uVar10,uVar18,
                     uVar50,uVar19,uVar20,uVar21,uVar23,uVar24,uVar26,uVar27,uVar28,uVar29,uVar30,
                     uVar31,uVar32,uVar33,uVar34,uVar35,uVar36,uVar37,uVar38,uVar39,uVar41,uVar40,
                     uVar42,uVar43,uVar44,uVar45,uVar46,uVar47,uVar48,uVar49,in_context);
    return uVar15;
  case 0x1011fa53:
    uVar3 = ResumeGenerator(in_r0,0);
    uVar4 = ResumeGenerator(uVar3,1);
    uVar5 = ResumeGenerator(uVar3,2);
    uVar6 = ResumeGenerator(uVar3,3);
    uVar8 = ResumeGenerator(uVar3,4);
    uVar9 = ResumeGenerator(uVar3,5);
    uVar10 = ResumeGenerator(uVar3,6);
    uVar18 = ResumeGenerator(uVar3,7);
    uVar19 = ResumeGenerator(uVar3,8);
    uVar20 = ResumeGenerator(uVar3,9);
    ResumeGenerator(uVar3,10);
    uVar21 = ResumeGenerator(uVar3,0xb);
    uVar23 = ResumeGenerator(uVar3,0xc);
    uVar24 = ResumeGenerator(uVar3,0xd);
    uVar26 = ResumeGenerator(uVar3,0xe);
    uVar27 = ResumeGenerator(uVar3,0xf);
    uVar28 = ResumeGenerator(uVar3,0x10);
    uVar29 = ResumeGenerator(uVar3,0x11);
    uVar30 = ResumeGenerator(uVar3,0x12);
    uVar31 = ResumeGenerator(uVar3,0x13);
    uVar32 = ResumeGenerator(uVar3,0x14);
    uVar33 = ResumeGenerator(uVar3,0x15);
    uVar34 = ResumeGenerator(uVar3,0x16);
    uVar35 = ResumeGenerator(uVar3,0x17);
    uVar36 = ResumeGenerator(uVar3,0x18);
    uVar37 = ResumeGenerator(uVar3,0x19);
    uVar38 = ResumeGenerator(uVar3,0x1a);
    uVar39 = ResumeGenerator(uVar3,0x1b);
    uVar41 = ResumeGenerator(uVar3,0x1c);
    uVar40 = ResumeGenerator(uVar3,0x1d);
    uVar42 = ResumeGenerator(uVar3,0x1e);
    uVar43 = ResumeGenerator(uVar3,0x1f);
    uVar44 = ResumeGenerator(uVar3,0x20);
    uVar45 = ResumeGenerator(uVar3,0x21);
    uVar46 = ResumeGenerator(uVar3,0x22);
    uVar47 = ResumeGenerator(uVar3,0x23);
    uVar48 = ResumeGenerator(uVar3,0x24);
    uVar49 = ResumeGenerator(uVar3,0x25);
    uVar50 = ResumeGenerator(uVar3,0x26);
    ResumeGenerator(uVar3,0x27);
    iVar7 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar7 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    uVar15 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar20,a0);
    iVar7 = _0x22b0fb.promises;
    uVar14 = CallProperty(iVar7.mkdir,iVar7,uVar15);
    uVar14 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar3,uVar14);
    SuspendGenerator(uVar3,uVar3,uVar4,uVar5,uVar6,uVar8,uVar9,uVar10,uVar18,uVar19,uVar20,uVar15,
                     uVar21,uVar23,uVar24,uVar26,uVar27,uVar28,uVar29,uVar30,uVar31,uVar32,uVar33,
                     uVar34,uVar35,uVar36,uVar37,uVar38,uVar39,uVar41,uVar40,uVar42,uVar43,uVar44,
                     uVar45,uVar46,uVar47,uVar48,uVar49,uVar50,in_context);
    return uVar14;
  case 0x10120204:
    uVar3 = ResumeGenerator(in_r0,0);
    uVar4 = ResumeGenerator(uVar3,1);
    uVar5 = ResumeGenerator(uVar3,2);
    uVar6 = ResumeGenerator(uVar3,3);
    uVar8 = ResumeGenerator(uVar3,4);
    uVar9 = ResumeGenerator(uVar3,5);
    uVar10 = ResumeGenerator(uVar3,6);
    uVar18 = ResumeGenerator(uVar3,7);
    uVar19 = ResumeGenerator(uVar3,8);
    uVar20 = ResumeGenerator(uVar3,9);
    uVar21 = ResumeGenerator(uVar3,10);
    uVar23 = ResumeGenerator(uVar3,0xb);
    uVar24 = ResumeGenerator(uVar3,0xc);
    uVar26 = ResumeGenerator(uVar3,0xd);
    iVar17 = ResumeGenerator(uVar3,0xe);
    uVar27 = ResumeGenerator(uVar3,0xf);
    uVar28 = ResumeGenerator(uVar3,0x10);
    uVar29 = ResumeGenerator(uVar3,0x11);
    uVar30 = ResumeGenerator(uVar3,0x12);
    uVar31 = ResumeGenerator(uVar3,0x13);
    uVar32 = ResumeGenerator(uVar3,0x14);
    uVar33 = ResumeGenerator(uVar3,0x15);
    uVar34 = ResumeGenerator(uVar3,0x16);
    uVar35 = ResumeGenerator(uVar3,0x17);
    uVar36 = ResumeGenerator(uVar3,0x18);
    uVar37 = ResumeGenerator(uVar3,0x19);
    uVar38 = ResumeGenerator(uVar3,0x1a);
    uVar39 = ResumeGenerator(uVar3,0x1b);
    uVar41 = ResumeGenerator(uVar3,0x1c);
    uVar40 = ResumeGenerator(uVar3,0x1d);
    uVar42 = ResumeGenerator(uVar3,0x1e);
    uVar43 = ResumeGenerator(uVar3,0x1f);
    uVar44 = ResumeGenerator(uVar3,0x20);
    uVar45 = ResumeGenerator(uVar3,0x21);
    uVar46 = ResumeGenerator(uVar3,0x22);
    uVar47 = ResumeGenerator(uVar3,0x23);
    uVar48 = ResumeGenerator(uVar3,0x24);
    uVar49 = ResumeGenerator(uVar3,0x25);
    uVar50 = ResumeGenerator(uVar3,0x26);
    ResumeGenerator(uVar3,0x27);
    iVar7 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar7 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    iVar7 = _0x22b0fb.promises;
    uVar15 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar21,iVar17.name);
    uVar15 = CallProperty(iVar7.rename,iVar7,uVar19,uVar15);
    uVar15 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar3,uVar15);
    SuspendGenerator(uVar3,uVar3,uVar4,uVar5,uVar6,uVar8,uVar9,uVar10,uVar18,uVar19,uVar20,uVar21,
                     uVar23,uVar24,uVar26,iVar17,uVar27,uVar28,uVar29,uVar30,uVar31,uVar32,uVar33,
                     uVar34,uVar35,uVar36,uVar37,uVar38,uVar39,uVar41,uVar40,uVar42,uVar43,uVar44,
                     uVar45,uVar46,uVar47,uVar48,uVar49,uVar50,in_context,"HtPsv");
    return uVar15;
  case 0x10120706:
    uVar3 = ResumeGenerator(in_r0,0);
    uVar8 = ResumeGenerator(uVar3,1);
    uVar9 = ResumeGenerator(uVar3,2);
    iVar17 = ResumeGenerator(uVar3,3);
    uVar10 = ResumeGenerator(uVar3,4);
    uVar18 = ResumeGenerator(uVar3,5);
    pcVar11 = ResumeGenerator(uVar3,6);
    iVar7 = ResumeGenerator(uVar3,7);
    uVar19 = ResumeGenerator(uVar3,8);
    uVar20 = ResumeGenerator(uVar3,9);
    uVar21 = ResumeGenerator(uVar3,10);
    iVar22 = ResumeGenerator(uVar3,0xb);
    uVar23 = ResumeGenerator(uVar3,0xc);
    uVar24 = ResumeGenerator(uVar3,0xd);
    iVar25 = ResumeGenerator(uVar3,0xe);
    uVar26 = ResumeGenerator(uVar3,0xf);
    uVar27 = ResumeGenerator(uVar3,0x10);
    uVar28 = ResumeGenerator(uVar3,0x11);
    uVar29 = ResumeGenerator(uVar3,0x12);
    uVar30 = ResumeGenerator(uVar3,0x13);
    uVar31 = ResumeGenerator(uVar3,0x14);
    uVar32 = ResumeGenerator(uVar3,0x15);
    uVar33 = ResumeGenerator(uVar3,0x16);
    uVar34 = ResumeGenerator(uVar3,0x17);
    uVar35 = ResumeGenerator(uVar3,0x18);
    uVar36 = ResumeGenerator(uVar3,0x19);
    uVar37 = ResumeGenerator(uVar3,0x1a);
    uVar38 = ResumeGenerator(uVar3,0x1b);
    uVar39 = ResumeGenerator(uVar3,0x1c);
    uVar41 = ResumeGenerator(uVar3,0x1d);
    uVar6 = ResumeGenerator(uVar3,0x1e);
    iVar13 = ResumeGenerator(uVar3,0x1f);
    ResumeGenerator(uVar3,0x20);
    iVar12 = ResumeGenerator(uVar3,0x21);
    in_r34 = ResumeGenerator(uVar3,0x22);
    uVar4 = ResumeGenerator(uVar3,0x23);
    in_r36 = ResumeGenerator(uVar3,0x24);
    ResumeGenerator(uVar3,0x25);
    ResumeGenerator(uVar3,0x26);
    ResumeGenerator(uVar3,0x27);
    ResumeGenerator(uVar3,0x28);
    iVar16 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar16 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    iVar7 = iVar7 + 1;
    break;
  case 0x101216ac:
    uVar3 = ResumeGenerator(in_r0,0);
    ResumeGenerator(uVar3,1);
    ResumeGenerator(uVar3,2);
    ResumeGenerator(uVar3,3);
    ResumeGenerator(uVar3,4);
    ResumeGenerator(uVar3,5);
    pcVar11 = ResumeGenerator(uVar3,6);
    iVar7 = ResumeGenerator(uVar3,7);
    ResumeGenerator(uVar3,8);
    ResumeGenerator(uVar3,9);
    ResumeGenerator(uVar3,10);
    ResumeGenerator(uVar3,0xb);
    ResumeGenerator(uVar3,0xc);
    ResumeGenerator(uVar3,0xd);
    ResumeGenerator(uVar3,0xe);
    ResumeGenerator(uVar3,0xf);
    ResumeGenerator(uVar3,0x10);
    ResumeGenerator(uVar3,0x11);
    ResumeGenerator(uVar3,0x12);
    ResumeGenerator(uVar3,0x13);
    ResumeGenerator(uVar3,0x14);
    ResumeGenerator(uVar3,0x15);
    ResumeGenerator(uVar3,0x16);
    ResumeGenerator(uVar3,0x17);
    ResumeGenerator(uVar3,0x18);
    ResumeGenerator(uVar3,0x19);
    ResumeGenerator(uVar3,0x1a);
    ResumeGenerator(uVar3,0x1b);
    ResumeGenerator(uVar3,0x1c);
    ResumeGenerator(uVar3,0x1d);
    ResumeGenerator(uVar3,0x1e);
    ResumeGenerator(uVar3,0x1f);
    ResumeGenerator(uVar3,0x20);
    uVar4 = ResumeGenerator(uVar3,0x21);
    uVar5 = ResumeGenerator(uVar3,0x22);
    ResumeGenerator(uVar3,0x23);
    ResumeGenerator(uVar3,0x24);
    ResumeGenerator(uVar3,0x25);
    ResumeGenerator(uVar3,0x26);
    ResumeGenerator(uVar3,0x27);
    ResumeGenerator(uVar3,0x28);
    iVar17 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar17 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    bVar2 = (boolean)IsJSReceiver(in_acc);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,in_acc);
    }
LAB_101216df:
                    /* WARNING: Switch is manually overridden */
    uVar4 = SwitchTarget(uVar4,0x1be,2,0);
    switch(uVar4) {
    case 0x101216f0:
      ReThrow(uVar5);
      return uVar5;
    case 0x101216f3:
      uVar3 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar3,uVar5,true);
      return uVar3;
    }
    if (iVar7 < 1) {
      iVar7 = api.gameWindow.webContents;
      CallProperty(iVar7.send,iVar7,"<MASKED-32>",
                   "<b>ModReportsManager : </b>There is no moderation report to merge for date : " +
                   a0 + ".");
    }
    else {
      iVar17 = api.gameWindow.webContents;
      CallProperty(iVar17.send,iVar17,"<MASKED-34>",
                   "<b>ModReportsManager : </b>" + iVar7 +
                   " moderation reports merged and backed up for date : " + a0 + ".");
    }
    uVar3 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar3,pcVar11,true);
    return uVar3;
  }
  uVar5 = CallProperty(uVar6,iVar13);
  uVar5 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar3,uVar5);
  SuspendGenerator(uVar3,uVar3,uVar8,uVar9,iVar17,uVar10,uVar18,pcVar11,iVar7,uVar19,uVar20,uVar21,
                   iVar22,uVar23,uVar24,iVar25,uVar26,uVar27,uVar28,uVar29,uVar30,uVar31,uVar32,
                   uVar33,uVar34,uVar35,uVar36,uVar37,uVar38,uVar39,uVar41,uVar6,iVar13,true,iVar12,
                   in_r34,uVar4,in_r36);
  return uVar5;
}
/* _0x52a050 [lit 421, 1 args] <- 9581 */
undefined4 _0x52a050(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope__0x52a050);
  uVar1 = CallProperty(a0.split,a0,"-");
  uVar2 = GetProperty(uVar1,0);
  uVar2 = Call(parseInt,uVar2);
  iVar3 = Call(isNaN,uVar2);
  if (iVar3 != 0) {
    return false;
  }
  uVar2 = GetProperty(uVar1,1);
  iVar3 = Call(parseInt,uVar2);
  iVar4 = Call(isNaN,iVar3);
  if (((iVar4 == 0) && (0 < iVar3)) && (iVar3 < 0xd)) {
    uVar1 = GetProperty(uVar1,2);
    iVar3 = Call(parseInt,uVar1);
    iVar4 = Call(isNaN,iVar3);
    if ((iVar4 == 0) && (iVar4 = (int)(iVar3 < 1), iVar4 == 0)) {
      iVar4 = (int)(0x1f < iVar3);
    }
    return (int)(iVar4 == 0);
  }
  return false;
}
/* _0x57b8ca [lit 422, 5 args] <- _0x52a050 */
undefined4 _0x57b8ca(undefined4 receiver,int a0,int a1,undefined4 a2,undefined4 a3,int a4)
{
  uVar1 = Call(_0xd37c14,a0 - a0_0x165979._0x2c1168,a1 + -5,a4 - a0_0x165979._0x54679d,a3,a4 + -0xf)
  ;
  return uVar1;
}
/* _0x445553 [lit 427, 1 args] <- 9581 */
char[] _0x445553(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope__0x445553);
  pcVar2 = "";
  for (iVar4 = 0; iVar4 < (int)a0.length; iVar4 = iVar4 + 1) {
    pcVar3 = GetProperty(a0,iVar4);
    cVar1 = LooseEquals("\n",pcVar3);
    if ((cVar1 != '\0') || (cVar1 = LooseEquals("\r",pcVar3), cVar1 != '\0')) {
      pcVar3 = "|/|</w:t><w:br/><w:t>|/|";
    }
    pcVar2 = pcVar2 + pcVar3;
  }
  return pcVar2;
}
/* anonymous_445 [lit 445, 1 args] <- 9581 */
undefined4 anonymous_445(undefined4 receiver,undefined4 a0)
{
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar2 = CreateFunctionContext(scope_anonymous_445);
    uVar3 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
    uVar4 = CreateClosure(_0x55cde8);
    uVar5 = CreateClosure(_0x1a8117);
    cVar1 = IsUndetectable(a0);
    if (cVar1 == '\0') {
      iVar6 = Call(_0x52a050,a0);
      if (iVar6 == 0) {
        iVar6 = api.gameWindow.webContents;
        CallProperty(iVar6.send,iVar6,"<MASKED-32>",
                     "<b>ModReportsManager : </b>Your date string is invalid (format : YYYY-M-D)");
        uVar2 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar3,undefined,true);
        return uVar2;
      }
    }
    else {
      iVar6 = api.utils;
      a0 = CallProperty(iVar6.getCurrentDate,iVar6);
    }
    uVar7 = Call(_0x36384b,a0);
    uVar7 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar3,uVar7);
    SuspendGenerator(uVar3,uVar3,uVar4,uVar5,in_r3,in_r4,in_r5,in_r6,in_r7,in_context,uVar2);
    return uVar7;
  }
  uVar2 = GeneratorResumeTarget(in_r0,0,2);
  switch(uVar2) {
  case 0x1012caa7:
    uVar2 = ResumeGenerator(in_r0,0);
    uVar3 = ResumeGenerator(uVar2,1);
    uVar4 = ResumeGenerator(uVar2,2);
    ResumeGenerator(uVar2,3);
    ResumeGenerator(uVar2,4);
    ResumeGenerator(uVar2,5);
    uVar5 = ResumeGenerator(uVar2,6);
    uVar7 = ResumeGenerator(uVar2,7);
    uVar11 = ResumeGenerator(uVar2,8);
    uVar12 = ResumeGenerator(uVar2,9);
    iVar6 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar2);
    if (iVar6 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    cVar1 = IsUndetectable(in_acc);
    if ((cVar1 == '\0') && (cVar1 = LooseEquals(0,in_acc.length), cVar1 == '\0')) {
      uVar8 = CallProperty(_0x28cd34.getPath,_0x28cd34,"userData");
      uVar8 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar8,"RetroReports");
      uVar9 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar8,a0);
      iVar6 = _0x22b0fb.promises;
      uVar10 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar9,"merged.html");
      uVar10 = CallProperty(iVar6.writeFile,iVar6,uVar10,in_acc);
      uVar10 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar2,uVar10);
      SuspendGenerator(uVar2,uVar2,uVar3,uVar4,in_acc,uVar8,uVar9,uVar5,uVar7,uVar11,uVar12,
                       in_context,"TNVcO");
      return uVar10;
    }
    break;
  case 0x1012d621:
    uVar2 = ResumeGenerator(in_r0,0);
    ResumeGenerator(uVar2,1);
    ResumeGenerator(uVar2,2);
    ResumeGenerator(uVar2,3);
    ResumeGenerator(uVar2,4);
    ResumeGenerator(uVar2,5);
    ResumeGenerator(uVar2,6);
    ResumeGenerator(uVar2,7);
    ResumeGenerator(uVar2,8);
    ResumeGenerator(uVar2,9);
    ResumeGenerator(uVar2,10);
    ResumeGenerator(uVar2,0xb);
    iVar6 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar2);
    if (iVar6 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    iVar6 = api.gameWindow.webContents;
    CallProperty(iVar6.send,iVar6,"<MASKED-34>",
                 "<b>ModReportsManager : </b>Merged HTML file created successfully.");
  }
  uVar2 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar2,undefined,true);
  return uVar2;
}
/* anonymous_457 [lit 457, 0 args] <- 9581 */
undefined4 anonymous_457(undefined4 receiver)
{
  boolean bVar2;
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar3 = CreateFunctionContext(scope_anonymous_457);
    uVar4 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
    uVar5 = CreateClosure(_0x44e133);
    uVar6 = CreateClosure(_0x4cba12);
    uVar7 = CallProperty(_0x28cd34.getPath,_0x28cd34,"userData");
    uVar7 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar7,"RetroReports");
    iVar8 = _0x22b0fb.promises;
    uVar9 = CallProperty(iVar8.opendir,iVar8,uVar7);
    uVar9 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar4,uVar9);
    SuspendGenerator(uVar4,uVar4,uVar5,uVar6,uVar7,in_r4,in_r5,in_r6,in_r7,in_r8,in_r9,in_r10,in_r11
                     ,in_r12,in_r13,in_r14,in_context,uVar3,uVar3);
    return uVar9;
  }
  uVar3 = GeneratorResumeTarget(in_r0,0,4);
  switch(uVar3) {
  case 0x1013044b:
    uVar3 = ResumeGenerator(in_r0,0);
    uVar4 = ResumeGenerator(uVar3,1);
    uVar5 = ResumeGenerator(uVar3,2);
    uVar6 = ResumeGenerator(uVar3,3);
    ResumeGenerator(uVar3,4);
    ResumeGenerator(uVar3,5);
    ResumeGenerator(uVar3,6);
    ResumeGenerator(uVar3,7);
    iVar8 = ResumeGenerator(uVar3,8);
    iVar18 = ResumeGenerator(uVar3,9);
    uVar7 = ResumeGenerator(uVar3,10);
    uVar9 = ResumeGenerator(uVar3,0xb);
    uVar19 = ResumeGenerator(uVar3,0xc);
    uVar20 = ResumeGenerator(uVar3,0xd);
    uVar21 = ResumeGenerator(uVar3,0xe);
    uVar22 = ResumeGenerator(uVar3,0xf);
    uVar23 = ResumeGenerator(uVar3,0x10);
    ResumeGenerator(uVar3,0x11);
    iVar10 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar10 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    iVar10 = api.utils;
    iVar10 = CallProperty(iVar10.getDirectories,iVar10,uVar6);
    iVar15 = 0;
    iVar16 = 0;
    while( true ) {
      if ((int)iVar10.length <= iVar16) {
        if (iVar15 < 1) {
          iVar8 = api.gameWindow.webContents;
          CallProperty(iVar8.send,iVar8,"<MASKED-34>",
                       "<b>ModReportsManager : </b>There is no pending moderation report, well done !"
        }
        else {
          iVar8 = api.gameWindow.webContents;
          CallProperty(iVar8.send,iVar8,"<MASKED-32>",
                       "<b>ModReportsManager : </b>Total pending moderation reports count : " +
                       iVar15);
        }
        uVar3 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar3,undefined,true);
        return uVar3;
      }
      uVar11 = GetProperty(iVar10,iVar16);
      iVar12 = Call(_0x52a050,uVar11);
      if (iVar12 != 0) break;
LAB_10132457:
      iVar16 = iVar16 + 1;
    }
    iVar12 = _0x22b0fb.promises;
    uVar13 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar6,uVar11);
    uVar13 = CallProperty(iVar12.opendir,iVar12,uVar13);
    uVar13 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar3,uVar13);
    SuspendGenerator(uVar3,uVar3,uVar4,uVar5,uVar6,iVar10,iVar15,iVar16,uVar11,iVar8,iVar18,uVar7,
                     uVar9,uVar19,uVar20,uVar21,uVar22,uVar23);
    return uVar13;
  case 0x101319e2:
    uVar3 = ResumeGenerator(in_r0,0);
    uVar4 = ResumeGenerator(uVar3,1);
    uVar5 = ResumeGenerator(uVar3,2);
    uVar6 = ResumeGenerator(uVar3,3);
    iVar10 = ResumeGenerator(uVar3,4);
    iVar15 = ResumeGenerator(uVar3,5);
    iVar16 = ResumeGenerator(uVar3,6);
    iVar17 = ResumeGenerator(uVar3,7);
    iVar8 = ResumeGenerator(uVar3,8);
    iVar18 = ResumeGenerator(uVar3,9);
    uVar7 = ResumeGenerator(uVar3,10);
    uVar9 = ResumeGenerator(uVar3,0xb);
    uVar19 = ResumeGenerator(uVar3,0xc);
    uVar20 = ResumeGenerator(uVar3,0xd);
    uVar21 = ResumeGenerator(uVar3,0xe);
    uVar22 = ResumeGenerator(uVar3,0xf);
    uVar23 = ResumeGenerator(uVar3,0x10);
    uVar13 = ResumeGenerator(uVar3,0x11);
    iVar24 = ResumeGenerator(uVar3,0x12);
    iVar25 = ResumeGenerator(uVar3,0x13);
    iVar12 = ResumeGenerator(uVar3,0x14);
    in_r21 = ResumeGenerator(uVar3,0x15);
    uVar11 = ResumeGenerator(uVar3,0x16);
    ResumeGenerator(uVar3,0x17);
    iVar26 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar26 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    bVar2 = (boolean)IsJSReceiver(in_acc);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,in_acc);
    }
    if (in_acc.done != 0) {
      uVar11 = 0xffffffff;
      iVar26 = -1;
      if (iVar25 == 0) {
        iVar12 = iVar24.return;
        if ((iVar12 != undefined) && (iVar12 != null)) {
          uVar11 = CallProperty(iVar12,iVar24);
          uVar11 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar3,uVar11);
          SuspendGenerator(uVar3,uVar3,uVar4,uVar5,uVar6,iVar10,iVar15,iVar16,iVar17,iVar8,iVar18,
                           uVar7,uVar9,uVar19,uVar20,uVar21,uVar22,uVar23,uVar13,iVar24,0,0xffffffff
                           ,0xffffffff,in_pending_message,in_acc,in_acc,0,in_context,iVar12);
          return uVar11;
        }
      }
      goto LAB_10131e10;
    }
    iVar25 = in_acc.value;
    iVar26 = iVar25.name;
    iVar14 = CallProperty(iVar26.startsWith,iVar26,"~");
    iVar26 = iVar25;
    in_r23 = iVar25;
    if (iVar14 == 0) {
      iVar14 = iVar25.name;
      iVar14 = CallProperty(iVar14.split,iVar14,".");
      uVar7 = CallProperty(iVar14.pop,iVar14);
      cVar1 = LooseEquals("docx",uVar7);
      if (cVar1 != '\0') {
        iVar14 = iVar25.name;
        uVar7 = CallProperty(iVar14.substring,iVar14,0,iVar25.name.length + -5);
        CallProperty(iVar18.push,iVar18,uVar7);
      }
    }
    goto LAB_101319c9;
  case 0x10131ddd:
    uVar3 = ResumeGenerator(in_r0,0);
    uVar4 = ResumeGenerator(uVar3,1);
    uVar5 = ResumeGenerator(uVar3,2);
    uVar6 = ResumeGenerator(uVar3,3);
    iVar10 = ResumeGenerator(uVar3,4);
    iVar15 = ResumeGenerator(uVar3,5);
    iVar16 = ResumeGenerator(uVar3,6);
    iVar17 = ResumeGenerator(uVar3,7);
    iVar8 = ResumeGenerator(uVar3,8);
    iVar18 = ResumeGenerator(uVar3,9);
    uVar7 = ResumeGenerator(uVar3,10);
    uVar9 = ResumeGenerator(uVar3,0xb);
    uVar19 = ResumeGenerator(uVar3,0xc);
    uVar20 = ResumeGenerator(uVar3,0xd);
    uVar21 = ResumeGenerator(uVar3,0xe);
    uVar22 = ResumeGenerator(uVar3,0xf);
    uVar23 = ResumeGenerator(uVar3,0x10);
    ResumeGenerator(uVar3,0x11);
    ResumeGenerator(uVar3,0x12);
    ResumeGenerator(uVar3,0x13);
    iVar26 = ResumeGenerator(uVar3,0x14);
    uVar11 = ResumeGenerator(uVar3,0x15);
    ResumeGenerator(uVar3,0x16);
    ResumeGenerator(uVar3,0x17);
    ResumeGenerator(uVar3,0x18);
    ResumeGenerator(uVar3,0x19);
    ResumeGenerator(uVar3,0x1a);
    ResumeGenerator(uVar3,0x1b);
    iVar12 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar12 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    bVar2 = (boolean)IsJSReceiver(in_acc);
    if (!bVar2) {
      CallRuntime(%ThrowIteratorResultNotAnObject,in_acc);
    }
LAB_10131e10:
    if (iVar26 == 0) {
      ReThrow(uVar11);
      return uVar11;
    }
    if ((int)iVar18.length < 1) goto LAB_10132457;
    iVar15 = iVar15 + iVar18.length;
    iVar12 = api.gameWindow.webContents;
    iVar26 = CallProperty(iVar18.join,iVar18,"\n  ");
    CallProperty(iVar12.send,iVar12,"<MASKED-27>",
                 "<b>ModReportsManager : </b>" + iVar18.length +
                 " pending moderation reports found for date : " + iVar17 + "\n  " + iVar26);
    goto LAB_10132457;
  }
  uVar3 = ResumeGenerator(in_r0,0);
  uVar4 = ResumeGenerator(uVar3,1);
  uVar5 = ResumeGenerator(uVar3,2);
  uVar6 = ResumeGenerator(uVar3,3);
  iVar10 = ResumeGenerator(uVar3,4);
  iVar15 = ResumeGenerator(uVar3,5);
  iVar16 = ResumeGenerator(uVar3,6);
  iVar17 = ResumeGenerator(uVar3,7);
  ResumeGenerator(uVar3,8);
  ResumeGenerator(uVar3,9);
  iVar25 = ResumeGenerator(uVar3,10);
  uVar9 = ResumeGenerator(uVar3,0xb);
  iVar26 = ResumeGenerator(uVar3,0xc);
  uVar20 = ResumeGenerator(uVar3,0xd);
  uVar21 = ResumeGenerator(uVar3,0xe);
  uVar22 = ResumeGenerator(uVar3,0xf);
  uVar23 = ResumeGenerator(uVar3,0x10);
  iVar8 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
  if (iVar8 != 0) {
    ReThrow(in_acc);
    return in_acc;
  }
  iVar18 = Construct(Array);
  iVar12 = in_acc.name_235;
  if ((iVar12 == undefined) || (iVar12 == null)) {
LAB_1013199f:
    iVar12 = CallProperty(in_acc.name_236,in_acc);
    iVar24 = InvokeIntrinsic(%_CreateAsyncFromSyncIterator,iVar12);
  }
  else {
    iVar24 = CallProperty(iVar12,in_acc);
    bVar2 = (boolean)IsJSReceiver(iVar24);
    if (!bVar2) {
      CallRuntime(%ThrowSymbolAsyncIteratorInvalid);
      goto LAB_1013199f;
    }
  }
  uVar13 = iVar24.next;
  iVar8 = in_acc;
  uVar11 = in_context;
LAB_101319c9:
  uVar7 = CallProperty(uVar13,iVar24);
  uVar7 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar3,uVar7);
  SuspendGenerator(uVar3,uVar3,uVar4,uVar5,uVar6,iVar10,iVar15,iVar16,iVar17,iVar8,iVar18,iVar25,
                   uVar9,iVar26,uVar20,uVar21,uVar22,uVar23,uVar13,iVar24,true,iVar12,in_r21,uVar11,
                   in_r23);
  return uVar7;
}
/* anonymous_470 [lit 470, 1 args] <- 9581 */
undefined4 anonymous_470(undefined4 receiver,undefined4 a0)
{
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar2 = CreateFunctionContext(scope_anonymous_470);
    uVar3 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
    uVar4 = CreateClosure(_0x3e1cd1);
    cVar1 = IsUndetectable(a0);
    if (cVar1 == '\0') {
      iVar5 = Call(_0x52a050,a0);
      if (iVar5 == 0) {
        iVar5 = api.gameWindow.webContents;
        CallProperty(iVar5.send,iVar5,"<MASKED-32>",
                     "<b>ModReportsManager : </b>Your date string is invalid (format : YYYY-M-D)");
        uVar2 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar3,undefined,true);
        return uVar2;
      }
    }
    else {
      iVar5 = api.utils;
      a0 = CallProperty(iVar5.getCurrentDate,iVar5);
    }
    uVar6 = Call(_0x36384b,a0);
    uVar6 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar3,uVar6);
    SuspendGenerator(uVar3,uVar3,uVar4,in_r2,in_r3,in_r4,in_r5,in_r6,in_r7,in_r8,in_r9,in_r10,
                     in_context,uVar2,"rykPw");
    return uVar6;
  }
  uVar2 = GeneratorResumeTarget(in_r0,0,3);
  switch(uVar2) {
  case 0x10135c85:
    uVar2 = ResumeGenerator(in_r0,0);
    uVar3 = ResumeGenerator(uVar2,1);
    ResumeGenerator(uVar2,2);
    ResumeGenerator(uVar2,3);
    ResumeGenerator(uVar2,4);
    uVar4 = ResumeGenerator(uVar2,5);
    uVar6 = ResumeGenerator(uVar2,6);
    uVar9 = ResumeGenerator(uVar2,7);
    uVar10 = ResumeGenerator(uVar2,8);
    uVar11 = ResumeGenerator(uVar2,9);
    uVar12 = ResumeGenerator(uVar2,10);
    uVar13 = ResumeGenerator(uVar2,0xb);
    uVar14 = ResumeGenerator(uVar2,0xc);
    uVar15 = ResumeGenerator(uVar2,0xd);
    iVar5 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar2);
    if (iVar5 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    cVar1 = IsUndetectable(in_acc);
    if ((cVar1 == '\0') && (cVar1 = LooseEquals(0,in_acc.length), cVar1 == '\0')) {
      uVar16 = CallProperty(_0x28cd34.getPath,_0x28cd34,"userData");
      uVar16 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar16,"RetroReports");
      uVar17 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar16,a0);
      iVar5 = _0x22b0fb.promises;
      uVar7 = CallProperty(iVar5.rmdir,iVar5,uVar17);
      uVar7 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar2,uVar7);
      SuspendGenerator(uVar2,uVar2,uVar3,in_acc,uVar16,uVar17,uVar4,uVar6,uVar9,uVar10,uVar11,uVar12
                       ,uVar13,uVar14,uVar15,in_context);
      return uVar7;
    }
    break;
  case 0x10136315:
    uVar2 = ResumeGenerator(in_r0,0);
    uVar3 = ResumeGenerator(uVar2,1);
    uVar4 = ResumeGenerator(uVar2,2);
    uVar6 = ResumeGenerator(uVar2,3);
    uVar9 = ResumeGenerator(uVar2,4);
    ResumeGenerator(uVar2,5);
    uVar10 = ResumeGenerator(uVar2,6);
    uVar11 = ResumeGenerator(uVar2,7);
    uVar12 = ResumeGenerator(uVar2,8);
    uVar13 = ResumeGenerator(uVar2,9);
    uVar14 = ResumeGenerator(uVar2,10);
    uVar15 = ResumeGenerator(uVar2,0xb);
    uVar16 = ResumeGenerator(uVar2,0xc);
    uVar17 = ResumeGenerator(uVar2,0xd);
    ResumeGenerator(uVar2,0xe);
    iVar5 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar2);
    if (iVar5 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    uVar7 = CreateClosure(anonymous_482);
    uVar7 = Call(uVar7,a0);
    uVar8 = CreateClosure(anonymous_488);
    iVar5 = CreateObjectLiteral({from, to, subject, html, text});
    iVar5.from = process.env.MODREPORTSMANAGER_MAIL_ADDRESS;
    iVar5.to = process.env.MODREPORTSMANAGER_MAIL_DESTINATIONS;
    iVar5.subject = uVar7;
    iVar5.html = uVar4;
    iVar5.text = "Rapport de moderation";
    uVar8 = Call(uVar8,iVar5);
    uVar8 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar2,uVar8);
    SuspendGenerator(uVar2,uVar2,uVar3,uVar4,uVar6,uVar9,uVar7,uVar10,uVar11,uVar12,uVar13,uVar14,
                     uVar15,uVar16,uVar17);
    return uVar8;
  case 0x1013677b:
    uVar2 = ResumeGenerator(in_r0,0);
    ResumeGenerator(uVar2,1);
    ResumeGenerator(uVar2,2);
    ResumeGenerator(uVar2,3);
    ResumeGenerator(uVar2,4);
    ResumeGenerator(uVar2,5);
    ResumeGenerator(uVar2,6);
    ResumeGenerator(uVar2,7);
    ResumeGenerator(uVar2,8);
    ResumeGenerator(uVar2,9);
    ResumeGenerator(uVar2,10);
    ResumeGenerator(uVar2,0xb);
    ResumeGenerator(uVar2,0xc);
    ResumeGenerator(uVar2,0xd);
    iVar5 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar2);
    if (iVar5 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
  }
  uVar2 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar2,undefined,true);
  return uVar2;
}
/* anonymous_482 [lit 482, 1 args] <- anonymous_470 */
char[] anonymous_482(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_482);
  uVar1 = CallProperty(a0.split,a0,"-");
  uVar2 = GetProperty(uVar1,0);
  iVar3 = Call(parseInt,uVar2);
  uVar2 = GetProperty(uVar1,1);
  pcVar4 = Call(parseInt,uVar2);
  uVar1 = GetProperty(uVar1,2);
  pcVar5 = Call(parseInt,uVar1);
  if (pcVar4 < 10) {
    pcVar4 = "0" + pcVar4;
  }
  if (pcVar5 < 10) {
    pcVar5 = "0" + pcVar5;
  }
  return "[DR - Rapport de Moderation] - " + pcVar5 + "/" + pcVar4 + "/" + iVar3;
}
/* anonymous_488 [lit 488, 1 args] <- anonymous_470 */
undefined4 anonymous_488(undefined4 receiver,int a0)
{
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar1 = CreateFunctionContext(scope_anonymous_488);
    uVar2 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
    uVar3 = CreateClosure(_0x49cbd3);
    uVar4 = CreateClosure(anonymous_494);
    uVar4 = Call(uVar4);
    uVar4 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar2,uVar4);
    SuspendGenerator(uVar2,uVar2,uVar3,in_r2,in_r3,in_r4,in_r5,in_r6,in_r7,in_r8,in_r9,in_context,
                     uVar1,uVar1);
    return uVar4;
  }
  uVar1 = GeneratorResumeTarget(in_r0,0,2);
  switch(uVar1) {
  case 0x1013c3d3:
    uVar1 = ResumeGenerator(in_r0,0);
    ResumeGenerator(uVar1,1);
    ResumeGenerator(uVar1,2);
    ResumeGenerator(uVar1,3);
    ResumeGenerator(uVar1,4);
    ResumeGenerator(uVar1,5);
    ResumeGenerator(uVar1,6);
    ResumeGenerator(uVar1,7);
    ResumeGenerator(uVar1,8);
    ResumeGenerator(uVar1,9);
    ResumeGenerator(uVar1,10);
    ResumeGenerator(uVar1,0xb);
    ResumeGenerator(uVar1,0xc);
    iVar6 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar1);
    if (iVar6 == 0) {
      iVar6 = api.gameWindow.webContents;
      CallProperty(iVar6.send,iVar6,"<MASKED-34>",
                   "<b>ModReportsManager : </b>Mail sent successfully to " + a0.to);
      uVar1 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar1,undefined,true);
      return uVar1;
    }
    ReThrow(in_acc);
    return in_acc;
  }
  uVar1 = ResumeGenerator(in_r0,0);
  uVar2 = ResumeGenerator(uVar1,1);
  uVar3 = ResumeGenerator(uVar1,2);
  uVar4 = ResumeGenerator(uVar1,3);
  uVar7 = ResumeGenerator(uVar1,4);
  uVar8 = ResumeGenerator(uVar1,5);
  uVar9 = ResumeGenerator(uVar1,6);
  uVar10 = ResumeGenerator(uVar1,7);
  uVar11 = ResumeGenerator(uVar1,8);
  ResumeGenerator(uVar1,9);
  uVar12 = ResumeGenerator(uVar1,10);
  uVar13 = ResumeGenerator(uVar1,0xb);
  uVar14 = ResumeGenerator(uVar1,0xc);
  iVar6 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar1);
  if (iVar6 == 0) {
    if (in_acc != 0) {
      uVar5 = CallProperty(in_acc.sendMail,in_acc,a0);
      uVar5 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar1,uVar5);
      SuspendGenerator(uVar1,uVar1,uVar2,uVar3,uVar4,uVar7,uVar8,uVar9,uVar10,uVar11,in_acc,uVar12,
                       uVar13,uVar14);
      return uVar5;
    }
    iVar6 = api.gameWindow.webContents;
    CallProperty(iVar6.send,iVar6,"<MASKED-32>",
                 "<b>ModReportsManager : </b>Mail transport not configured in your .env file");
    uVar1 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar1,undefined,true);
    return uVar1;
  }
  ReThrow(in_acc);
  return in_acc;
}
/* WARNING: Switch with 1 destination removed at 0x10140b7a */
/* anonymous_494 [lit 494, 0 args] <- anonymous_488 */
undefined4 anonymous_494(undefined4 receiver)
{
  iVar9 = _0x12435a;
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar2 = CreateFunctionContext(scope_anonymous_494);
    uVar3 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
    uVar4 = CreateClosure(_0x1f7f31);
    uVar5 = CreateClosure(_0x74fe3e);
    if ((process.env.MODREPORTSMANAGER_MAIL_SERVICE == 0) &&
       (process.env.MODREPORTSMANAGER_MAIL_CUSTOM_CONF_STRING == 0)) {
      uVar2 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar3,undefined,true);
      return uVar2;
    }
    if (process.env.MODREPORTSMANAGER_MAIL_CUSTOM_CONF_STRING == 0) {
      iVar6 = process.env.MODREPORTSMANAGER_MAIL_SERVICE;
      uVar7 = CallProperty(iVar6.toLowerCase,iVar6);
      cVar1 = LooseEquals("gmail",uVar7);
      if (cVar1 != '\0') {
        CreateBlockContext(block_scope_anonymous_494);
        _0x3de64d = Construct(_0x1d14a2,process.env.MODREPORTSMANAGER_GMAIL_API_CLIENT_ID,
                              process.env.MODREPORTSMANAGER_GMAIL_API_CLIENT_SECRET,
                              "https://developers.google.com/oauthplayground");
        iVar9 = CreateEmptyObjectLiteral();
        iVar9.refresh_token = process.env.MODREPORTSMANAGER_GMAIL_API_REFRESH_TOKEN;
        CallProperty(_0x3de64d.setCredentials,_0x3de64d,iVar9);
        uVar7 = CreateClosure(anonymous_500);
        uVar7 = Construct(Promise,uVar7);
        uVar7 = InvokeIntrinsic(%_AsyncFunctionAwaitUncaught,uVar3,uVar7);
        SuspendGenerator(uVar3,uVar3,uVar4,uVar5,in_r3,in_r4,undefined,iVar9,in_r7,in_r8,in_r9,
                         in_context,uVar2,uVar2);
        return uVar7;
      }
      uVar2 = _0x12435a.createTransport;
      iVar6 = CreateObjectLiteral({service, auth});
      iVar6.service = process.env.MODREPORTSMANAGER_MAIL_SERVICE;
      iVar8 = CreateObjectLiteral({user, pass});
      iVar8.user = process.env.MODREPORTSMANAGER_MAIL_ADDRESS;
      iVar8.pass = process.env.MODREPORTSMANAGER_MAIL_PASS;
      iVar6.auth = iVar8;
      uVar2 = CallProperty(uVar2,iVar9,iVar6);
    }
    else {
      uVar2 = CallProperty(_0x12435a.createTransport,_0x12435a,
                           process.env.MODREPORTSMANAGER_MAIL_CUSTOM_CONF_STRING);
    }
  }
  else {
    GeneratorResumeTarget(in_r0,0,1);
    uVar3 = ResumeGenerator(in_r0,0);
    ResumeGenerator(uVar3,1);
    ResumeGenerator(uVar3,2);
    ResumeGenerator(uVar3,3);
    ResumeGenerator(uVar3,4);
    ResumeGenerator(uVar3,5);
    ResumeGenerator(uVar3,6);
    ResumeGenerator(uVar3,7);
    ResumeGenerator(uVar3,8);
    ResumeGenerator(uVar3,9);
    ResumeGenerator(uVar3,10);
    ResumeGenerator(uVar3,0xb);
    ResumeGenerator(uVar3,0xc);
    iVar9 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar3);
    if (iVar9 != 0) {
      ReThrow(in_acc);
      return in_acc;
    }
    iVar9 = CreateEmptyObjectLiteral();
    iVar9.type = "OAuth2";
    iVar9.user = process.env.MODREPORTSMANAGER_MAIL_ADDRESS;
    iVar9.accessToken = in_acc;
    iVar9.clientId = process.env.MODREPORTSMANAGER_GMAIL_API_CLIENT_ID;
    iVar9.clientSecret = process.env.MODREPORTSMANAGER_GMAIL_API_CLIENT_SECRET;
    iVar9.refreshToken = process.env.MODREPORTSMANAGER_GMAIL_API_REFRESH_TOKEN;
    iVar6 = CreateEmptyObjectLiteral();
    iVar6.service = "gmail";
    iVar6.auth = iVar9;
    uVar2 = CallProperty(_0x12435a.createTransport,_0x12435a,iVar6);
  }
  uVar2 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar3,uVar2,true);
  return uVar2;
}
/* anonymous_500 [lit 500, 2 args] <- anonymous_494 */
undefined4 anonymous_500(undefined4 receiver,undefined4 a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_500);
  _0x2f0d45 = a0;
  _0x5a5dac = a1;
  uVar1 = CreateClosure(anonymous_506);
  CallProperty(_0x3de64d.getAccessToken,_0x3de64d,uVar1);
  return undefined;
}
/* anonymous_506 [lit 506, 2 args] <- anonymous_500 */
undefined4 anonymous_506(undefined4 receiver,int a0,undefined4 a1)
{
  CreateFunctionContext(scope_anonymous_506);
  if (a0 != 0) {
    Call(_0x5a5dac,a0);
  }
  Call(_0x2f0d45,a1);
  return undefined;
}
/* WARNING: Switch with 1 destination removed at 0x101468ba */
/* anonymous_518 [lit 518, 10 args] <- 9581 */
undefined4
anonymous_518(undefined4 receiver,undefined4 a0,undefined4 a1,undefined4 a2,undefined4 a3,
             undefined4 a4,char[] a5,undefined4 a6,undefined4 a7,char[] a8,char[] a9)
{
  uVar9 = _0x2e94ba;
                    /* WARNING: Switch is manually overridden */
  if (in_r0 == undefined) {
    uVar2 = CreateFunctionContext(scope_anonymous_518);
    uVar3 = InvokeIntrinsic(%_AsyncFunctionEnter,in_closure,receiver);
    cVar1 = LooseEquals("null",a9);
    if (cVar1 != '\0') {
      a9 = "";
    }
    cVar1 = LooseEquals("null",a5);
    if (cVar1 != '\0') {
      a5 = "";
    }
    cVar1 = LooseEquals("null",a8);
    if (cVar1 != '\0') {
      a8 = "";
    }
    CreateBlockContext(block_scope_anonymous_518);
    _0x1cb957 = the_hole;
    uVar4 = CallProperty(_0x28cd34.getPath,_0x28cd34,"userData");
    uVar4 = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar4,"RetroReports/MODTEMPLATE.docx");
    uVar5 = CallProperty(_0x22b0fb.readFileSync,_0x22b0fb,uVar4);
    iVar6 = CreateObjectLiteral({template, literalXmlDelimiter, data});
    _0x30d7c7 = a0;
    _0x5d59b9 = a2;
    _0x3832c6 = a3;
    iVar6.template = uVar5;
    iVar6.literalXmlDelimiter = _0x5becf3;
    iVar7 = CreateObjectLiteral({st, sn, sa, description, fa, penal, ...});
    iVar7.st = a1;
    iVar7.sn = _0x30d7c7;
    uVar8 = Call(_0x445553,a4);
    iVar7.sa = uVar8;
    uVar8 = Call(_0x445553,a5);
    iVar7.description = uVar8;
    uVar8 = Call(_0x445553,a6);
    iVar7.fa = uVar8;
    uVar8 = Call(_0x445553,a7);
    iVar7.penal = uVar8;
    uVar8 = Call(_0x445553,a8);
    iVar7.dj = uVar8;
    uVar8 = Call(_0x445553,a9);
    iVar7.ar = uVar8;
    iVar6.data = iVar7;
    uVar9 = Call(uVar9,iVar6);
    uVar9 = InvokeIntrinsic(%_AsyncFunctionAwaitCaught,uVar3,uVar9);
    SuspendGenerator(uVar3,uVar3,uVar4,in_r2,in_r3,in_r4,in_r5,in_r6,in_r7,in_r8,in_r9,in_r10,in_r11
                     ,uVar5,in_r13,in_context,uVar2,"smemx",uVar2,uVar2);
    return uVar9;
  }
  GeneratorResumeTarget(in_r0,0,1);
  uVar9 = ResumeGenerator(in_r0,0);
  ResumeGenerator(uVar9,1);
  ResumeGenerator(uVar9,2);
  ResumeGenerator(uVar9,3);
  ResumeGenerator(uVar9,4);
  ResumeGenerator(uVar9,5);
  ResumeGenerator(uVar9,6);
  ResumeGenerator(uVar9,7);
  ResumeGenerator(uVar9,8);
  ResumeGenerator(uVar9,9);
  ResumeGenerator(uVar9,10);
  ResumeGenerator(uVar9,0xb);
  ResumeGenerator(uVar9,0xc);
  ResumeGenerator(uVar9,0xd);
  ResumeGenerator(uVar9,0xe);
  ResumeGenerator(uVar9,0xf);
  ResumeGenerator(uVar9,0x10);
  ResumeGenerator(uVar9,0x11);
  ResumeGenerator(uVar9,0x12);
  iVar6 = InvokeIntrinsic(%_GeneratorGetResumeMode,uVar9);
  if (iVar6 != 0) {
    ReThrow(in_acc);
    return in_acc;
  }
  _0x1cb957 = in_acc;
  uVar2 = CallProperty(_0x28cd34.getPath,_0x28cd34,"userData");
  _0x50d52c = CallProperty(_0x46cc0e.join,_0x46cc0e,uVar2,"RetroReports");
  uVar2 = CreateEmptyObjectLiteral();
  uVar3 = CreateClosure(anonymous_530);
  CallProperty(_0x22b0fb.mkdir,_0x22b0fb,_0x50d52c,uVar2,uVar3);
  uVar9 = InvokeIntrinsic(%_AsyncFunctionResolve,uVar9,undefined,true);
  return uVar9;
}
/* anonymous_530 [lit 530, 1 args] <- anonymous_518 */
undefined4 anonymous_530(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_530);
  if ((a0 != 0) && (cVar1 = LooseEquals("EEXIST",a0.code), cVar1 == '\0')) {
    Throw(a0);
    return a0;
  }
  iVar2 = api.utils;
  uVar3 = CallProperty(iVar2.getCurrentDate,iVar2);
  _0x50d52c = CallProperty(_0x46cc0e.join,_0x46cc0e,_0x50d52c,uVar3);
  uVar3 = CreateEmptyObjectLiteral();
  uVar4 = CreateClosure(anonymous_536);
  CallProperty(_0x22b0fb.mkdir,_0x22b0fb,_0x50d52c,uVar3,uVar4);
  return undefined;
}
/* anonymous_536 [lit 536, 1 args] <- anonymous_530 */
undefined4 anonymous_536(undefined4 receiver,int a0)
{
  CreateFunctionContext(scope_anonymous_536);
  if ((a0 != 0) && (cVar1 = LooseEquals("EEXIST",a0.code), cVar1 == '\0')) {
    Throw(a0);
    return a0;
  }
  _0x4f6943 = _0x4f6943 + 1;
  uVar2 = CallProperty(_0x46cc0e.join,_0x46cc0e,_0x50d52c,
                       "." + _0x5d59b9 + _0x30d7c7 + "." + _0x3832c6 + "." + _0x4f6943 + ".docx");
  iVar3 = CallProperty(_0x22b0fb.createWriteStream,_0x22b0fb,uVar2);
  CallProperty(iVar3.write,iVar3,_0x1cb957);
  CallProperty(iVar3.end,iVar3);
  return undefined;
}
