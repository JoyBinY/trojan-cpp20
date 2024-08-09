# trojan

[![Build Status](https://dev.azure.com/GreaterFire/Trojan-GFW/_apis/build/status/trojan-gfw.trojan?branchName=master)](https://dev.azure.com/GreaterFire/Trojan-GFW/_build/latest?definitionId=5&branchName=master)

An unidentifiable mechanism that helps you bypass GFW.

Trojan features multiple protocols over `TLS` to avoid both active/passive detections and ISP `QoS` limitations.

Trojan is not a fixed program or protocol. It's an idea, an idea that imitating the most common service, to an extent that it behaves identically, could help you get across the Great FireWall permanently, without being identified ever. We are the GreatER Fire; we ship Trojan Horses.

## Documentations

An online documentation can be found [here](https://trojan-gfw.github.io/trojan/).  
Installation guide on various platforms can be found in the [wiki](https://github.com/trojan-gfw/trojan/wiki/Binary-&-Package-Distributions).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Dependencies

- [CMake](https://cmake.org/) >= 3.7.2
- [OpenSSL](https://www.openssl.org/) >= 1.1.0
- [asio](https://think-async.com/Asio/) >= 1.30.2
- [cxxopts](https://github.com/jarro2783/cxxopts/tags) >= 3.2.1
- [rapidjson](https://github.com/Tencent/rapidjson/tags) > 1.1.0
- [libmysqlclient](https://dev.mysql.com/downloads/connector/c/)

## License

[GPLv3](LICENSE)

## Build

PRO_DIR=/code/trojan-cpp20
INS_DIR=${PRO_DIR}/util/install
cmake -G"Ninja" -B${PRO_DIR}/.build -DCMAKE_INSTALL_PREFIX=${INS_DIR} -DCMAKE_PREFIX_PATH=${INS_DIR} -DENABLE_MYSQL=FALSE -DCMAKE_EXPORT_COMPILE_COMMANDS=1 . && cmake --build ${PRO_DIR}/.build
cmake -G"Ninja" -B${PRO_DIR}/.build -DCMAKE_INSTALL_PREFIX=${INS_DIR} -DCMAKE_PREFIX_PATH=${INS_DIR} -DENABLE_MYSQL=FALSE -DCMAKE_EXPORT_COMPILE_COMMANDS=1 . && cmake --build ${PRO_DIR}/.build -- install