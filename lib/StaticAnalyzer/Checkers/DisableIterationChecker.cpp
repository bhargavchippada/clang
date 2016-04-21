//== DisableIterationChecker.cpp - Allow no iteration in code ----------------
// C++---==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===-----------------------------------------------------------------------------===//
//
// This defines DisableIterationChecker, a builtin check in ExprEngine that
// performs checks for usage of iteration statements: for, while, do
//
// Author: Bhargav Chippada
//===-----------------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

#include "clang/AST/Expr.h"
#include "clang/AST/OperationKinds.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/Analysis/AnalysisContext.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/TypeTraits.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;

namespace {
class WalkAST : public StmtVisitor<WalkAST> {
  const CheckerBase *Checker;
  BugReporter &BR;
  AnalysisDeclContext *AC;

 public:
  WalkAST(const CheckerBase *checker, BugReporter &br, AnalysisDeclContext *ac)
      : Checker(checker), BR(br), AC(ac) {}

  void emitReport(Stmt *S, const char *Msg);

  // Statement visitor methods.
  void VisitChildren(Stmt *S);
  void VisitStmt(Stmt *S) { VisitChildren(S); }
  void VisitWhileStmt(WhileStmt *S);
  void VisitForStmt(ForStmt *S);
  void VisitDoStmt(DoStmt *S);
};
}  // end anonymous namespace

void WalkAST::emitReport(Stmt *S, const char *Msg) {
  PathDiagnosticLocation Loc =
      PathDiagnosticLocation::createBegin(S, BR.getSourceManager(), AC);
  SmallString<256> SmS;
  llvm::raw_svector_ostream os(SmS);
  os << Msg;
  BR.EmitBasicReport(AC->getDecl(), Checker, os.str(),
                     "Iteration Statements not allowed", os.str(), Loc,
                     S->getSourceRange());
}

void WalkAST::VisitWhileStmt(WhileStmt *S) {
  emitReport(S, "Iteration prohibited, Don't use While loop");
  // Recurse and check children.
  VisitChildren(S);
}

void WalkAST::VisitForStmt(ForStmt *S) {
  emitReport(S, "Iteration prohibited, Don't use For loop");
  // Recurse and check children.
  VisitChildren(S);
}

void WalkAST::VisitDoStmt(DoStmt *S) {
  emitReport(S, "Iteration prohibited, Don't use Do-While loop");
  // Recurse and check children.
  VisitChildren(S);
}

void WalkAST::VisitChildren(Stmt *S) {
  for (Stmt *Child : S->children())
    if (Child) Visit(Child);
}

namespace {
class DisableIterationChecker : public Checker<check::ASTCodeBody> {
 public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr,
                        BugReporter &BR) const {
    WalkAST walker(this, BR, Mgr.getAnalysisDeclContext(D));
    walker.Visit(D->getBody());
  }
};
}  // end anonymous namespace

void ento::registerDisableIterationChecker(CheckerManager &mgr) {
  mgr.registerChecker<DisableIterationChecker>();
}