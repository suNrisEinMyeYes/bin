# Lottery
Sibears training service

The service is made up of a Qt C++ service and a python3 subservice.

## Note on docker

При первом запуске в докере вы скорее всего увидите ошибку про невозможность подключиться к базе данных. Это связано с тем, что при первом запуске БД mysql не успевает вовремя включиться для сервиса. При повторных запусках эта проблема должна уйти, поскольку БД стартует достаточно быстро, чтобы уложиться в таймаут.

То есть если вы видите ошибку при запуске и сервис не стартует, то попробуйте подождать надписей от БД вроде "ready", выключить и попробовать запустить снова.

## Authors

Service, checker, description: d86leader

Sploits: [Alamov Vldimir](https://github.com/RockThisParty), [Komarova Tatyana](https://github.com/alex8h)

## Requirements

- C++17 compiler (g++>=8.0, clang++>=8.0, g++=9.0 works)
- QtCore, QtNetwork, QtSql >= 5.9 (5.14 works)
- libQt5Sql5-mysql for QtSql
- python3>=3.6.10
- mysql-connector-python==8.0.18
- systemctl

## Setup

1. To build: run `make` to build c++ service in th `build` directory
3. To start: run helper service with cwd `./helper`, it uses the ssl keys located there
4. To check: run the checker with cwd `./checker`, it uses the ssl keys located there

Checker also will dump and read its database to and from CWD.
