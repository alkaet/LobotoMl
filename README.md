# LobotoMl

## About
LobotoMl is a set of scripts and tools to assess production deployments of ML services.
LobotoMl is intended as a complement to model assessment tools like [CleverHans](https://github.com/cleverhans-lab/cleverhans) and [CounterFit](https://github.com/Azure/counterfit).

## Structure
LobotoML is currently composed of the following components and will grow in the future:
- mlmap: An Nmap script to identify production serving frameworks and their versions among the likes of Tensorflow Serving and PyTorch Serve. 
- ONNX_runtime_hacks: a proof of concept custom operation in ONNX runtime that has side effects and creates files on the target machine. This should be extended to run shellcode from ONNX.

## Getting Started
See the README files in each of the component folders.

## Warning and responsibility statement
This set of tool is intended for **educational and professional use on systems, software and models you are expressly authorized to attack only**. Do not run this set of tools against a system that you do not either own or have expressly been authorized to test. The LobotoMl team (aka me and any contributors) are not responsible for any legal issue that may ensue of the illegitimate use of this project.

## Contributing
This project is in its infancy but feel free to contribute. By contributing you agree that you have the right to and grant the right to use your contribution along the terms of the project license. 

## License
See the LICENSE file and individual license points in the individual component folders.
