QT -= gui
QT += network sql

CONFIG += c++1z console
CONFIG -= app_bundle

DEFINES += QT_DEPRECATED_WARNINGS

SOURCES += \
    Server.cpp \
    Store.cpp \
    StringGenerator.cpp \
    main.cpp

HEADERS += \
    Server.h \
    Store.h \
    StringGenerator.h \
    defines.h

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
