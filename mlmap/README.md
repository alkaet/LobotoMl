# MlMap

## About

Mlmap is a set of scripts to perform reconnaissance of ML production deployments.
MlMap currently only consists of the `ml-server-version.nse` Nmap script.

## Usage 
After intalling Nmap as described in the [manual](https://nmap.org/book/install.html), simply run the script as follows (replacing the ports, path and ip as appropriate):

```nmap -n --script /path/to/ml-server-version.nse ip.of.your.target -p target_ports```

## How does it work?

The Nmap script `ml-server-version.nse` identifies the server types and version using the default verbose API descriptions and custom error messages returned by the deployment frameworks.
The script sends some magic queries formated specifically to trigger responses from the server. The responses are then parsed for clues of the deployment server.

The script needs to directly interact with the target server as if it was a malicious connection client. It currently cannot identify deployments through proxies.

#### Notes
By default, PyTorch Serve only runs on localhost. It needs active intervention to expose the inferance, logging and management apis. The script currently only identifies the framework using the inference API. 
Extensions to other apis will soon come.

On the contrary, by default TensorFlow Serving runs on external interfaces making it a potential prime target. 

## License 

BSD 2-clause as compatible with [Nmap Licensing guidelines](https://nmap.org/book/man-legal.html#nmap-copyright).
