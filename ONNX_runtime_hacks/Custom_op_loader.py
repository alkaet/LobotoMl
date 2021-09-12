# based on the ORT tests
import os
import numpy as np
import onnxruntime as onnxrt
import threading
import sys
from onnxruntime.capi.onnxruntime_pybind11_state import Fail



def RegisterCustomOpsLibrary():
    if sys.platform.startswith("win"):
        shared_library = 'custom_op_library.dll'
        if not os.path.exists(shared_library):
            raise FileNotFoundError("Unable to find '{0}'".format(shared_library))

    elif sys.platform.startswith("darwin"):
        shared_library = 'libcustom_op_library.dylib'
        if not os.path.exists(shared_library):
            raise FileNotFoundError("Unable to find '{0}'".format(shared_library))

    else:
        shared_library = './libcustom_op_library.so'
        if not os.path.exists(shared_library):
            raise FileNotFoundError("Unable to find '{0}'".format(shared_library))

    this = os.path.dirname(__file__)
    custom_op_model = os.path.join(this, "custom_op_test.onnx")
    if not os.path.exists(custom_op_model):
        raise FileNotFoundError("Unable to find '{0}'".format(custom_op_model))

    so1 = onnxrt.SessionOptions()
    print("start")
    so1.register_custom_ops_library(shared_library)
    

    # Model loading successfully indicates that the custom op node could be resolved successfully
    sess1 = onnxrt.InferenceSession(custom_op_model, so1)
    #Run with input data
    input_name_0 = sess1.get_inputs()[0].name
    input_name_1 = sess1.get_inputs()[1].name
    output_name = sess1.get_outputs()[0].name
    input_0 = np.ones((3,5)).astype(np.float32)
    input_1 = np.zeros((3,5)).astype(np.float32)
    res = sess1.run([output_name], {input_name_0: input_0, input_name_1: input_1})
    output_expected = np.ones((3,5)).astype(np.float32)
    np.testing.assert_allclose(output_expected, res[0], rtol=1e-05, atol=1e-08)
    print("done assert")


    # Create an alias of SessionOptions instance
    # We will use this alias to construct another InferenceSession
    so2 = so1

    # Model loading successfully indicates that the custom op node could be resolved successfully
    sess2 = onnxrt.InferenceSession(custom_op_model, so2)

    # Create another SessionOptions instance with the same shared library referenced
    so3 = onnxrt.SessionOptions()
    so3.register_custom_ops_library(shared_library)
    sess3 = onnxrt.InferenceSession(custom_op_model, so3)



if __name__ == '__main__':
    print("register")
    RegisterCustomOpsLibrary()