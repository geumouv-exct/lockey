import importlib.util
import json
import os
import sys
import traceback
import unittest

path = sys.argv[1]
sys.path.insert(0, os.getcwd())
class Reporter(unittest.TestResult):
    def emit(self, test, passed, assertion=False):
        print('TRACE_TEST_EVENT:' + json.dumps({'name': test.id(), 'file': path, 'line': 0, 'passed': passed, 'assertion': assertion}), flush=True)
    def addSuccess(self, test):
        super().addSuccess(test)
        self.emit(test, True)
    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.emit(test, False, True)
        traceback.print_exception(*err, file=sys.stderr)
    def addError(self, test, err):
        super().addError(test, err)
        self.emit(test, False)
        traceback.print_exception(*err, file=sys.stderr)
    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.emit(subtest, False, issubclass(err[0], AssertionError))
            traceback.print_exception(*err, file=sys.stderr)
try:
    spec = importlib.util.spec_from_file_location('trace_selected_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    result = Reporter()
    suite.run(result)
    sys.exit(0 if result.wasSuccessful() else 1)
except Exception:
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)
