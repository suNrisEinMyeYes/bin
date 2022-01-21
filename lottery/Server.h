#pragma once

#include <QTcpServer>

#include "Store.h"

// Description: main TCP server in app

class Server : public QTcpServer
{
    Q_OBJECT

private slots:
    void gotConnection();

public:
    Server(QObject* parent = nullptr);
    virtual ~Server();
};


class ClientHandler : public QObject
{
    Q_OBJECT

    enum struct State : int
    {   LoginAwaitName = 0x0
    ,   LoginAwaitPass
    ,   RegAwaitPass

    ,   UserAwaitCommand = 0x10
    ,   UserAwaitTicket
    ,   UserAwaitExhangePartner
    ,   UserAwaitAcceptName
    ,   UserAwaitAcceptConfirm

    ,   AdminAwaitCommand = 0x20
    ,   AdminAwaitWinName
    ,   AdminAwaitWinNumber
    };


    QAbstractSocket* m_socket;

    User  m_subject;
    State m_state;
    User  m_object;

private slots:
    void gotData();

private:
    // handlers
    void loginName(QByteArray&&);
    void loginPass(QByteArray&&);
    void regPass(QByteArray&&);
    void userCommand(QByteArray&&);
    void userTicket(QByteArray&&);
    void userExhangePartner(QByteArray&&);
    void userAcceptName(QByteArray&&);
    void userAcceptConfirm(QByteArray&&);
    void adminCommand(QByteArray&&);
    void adminWinName(QByteArray&&);
    void adminWinNumber(QByteArray&&);
    // helpers
    void menuBanner();
    void reloadSubject();
    void reloadObject();

public:
    ClientHandler(QAbstractSocket*, QObject* parent = nullptr);
    virtual ~ClientHandler();
};
