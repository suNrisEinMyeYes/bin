FROM opensuse/leap:15.1

RUN zypper refresh \
    && zypper install -y \
        libQt5Network-devel libQt5Sql-devel gcc8-c++ make libQt5Sql5-mysql \
        python3 python3-pip \
    && pip3 install mysql-connector-python==8.0.18

RUN useradd -m lottery
ADD --chown=lottery:users \
    main.cpp Server.cpp Store.cpp StringGenerator.cpp \
    defines.h Server.h Store.h StringGenerator.h \
    Makefile oleg-service.pro \
    /home/lottery/
ADD --chown=lottery:users helper /home/lottery/helper

WORKDIR /home/lottery/helper
RUN make -C ..

CMD ["/usr/bin/env", "python3", "/home/lottery/helper/helper.py"]
