# ONNX runtime hacks

## About

The ONNX runtime hacks are a set of proof of concepts of attacks and exploits on the ONNX format and the [ONNX runtime](https://onnxruntime.ai/).
Currently this folder is limited to an example showing how to write ONNX custom operators which have side effects such as arbitrary file creation (contrary to the requirements of the [ONNX specification](https://github.com/onnx/onnx)). 

## Usage

Follow the [ONNX runtime build guide](https://onnxruntime.ai/docs/how-to/build/) rather than the installation guide. This will enaable you to write custom ONNX code.

Change directory to `onnxruntime/onnxruntime/test/testdata/custom_op_library/` and backup the file `custom_op_library.cc`.

Copy the proof of concept side effect inducing file there:
```cp /path/to/LobotoMl/ONNX_runtime_hacks/arbitrary_file_custom_op_library.cc ./custom_op_library.cc```

Then simply build the library again with `make` *et voilà !*

To run the arbitrary-file-creating model run the model loader in this repository:
```python3 /path/to/LobotoMl/ONNX_runtime_hacks/Custom_op_loader.py```

You can see the Model definition using the protocol buffer compiler:
```protoc --decode=onnx.ModelProto -I /path/to/onnxruntime/cmake/external/onnx/onnx/ /path/to/onnxruntime/cmake/external/onnx/onnx/onnx.proto3 <custom_op_test.onnx > Model.txt```

If you want to modify the architecture of the model you can also do so using `protoc`.

If you don't follow these instructions, you may have to modify the linker script file or cmake so that the symbols of your shared object library are correctly exported. 

## How it works

The code defines a custom ONNX compiler operator under the guise of performing an operation which is not implemented in the ONNX runtime.
On Linux, the malicious custom operator is compiled into a shared object library. 

The loader is derived from the [python API example](https://github.com/microsoft/onnxruntime/blob/master/onnxruntime/test/python/onnxruntime_test_python.py). 
This example automatically registers the custom op in the target ONNX model graph before running the model, meaning that the arbitrary shared object library will be automatically loaded and executed. 

You can modify the example model and corresponding protobuf to suit your needs.


## License 

The code is modified from the ONNX runtime is licensed with the MIT license linked [here](https://github.com/microsoft/onnxruntime/blob/master/LICENSE).
