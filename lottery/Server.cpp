#include "defines.h"
#include "Server.h"

#include <QByteArray>
#include <QDebug>
#include <QString>
#include <QTcpSocket>
#include "StringGenerator.h"


ClientHandler::~ClientHandler()
{
}
Server::~Server()
{
}


Server::Server(QObject* parent)
: QTcpServer (parent)
{
    connect( this, &Server::newConnection
           , this, &Server::gotConnection
           );
}

void Server::gotConnection()
{
    auto* sock = this->nextPendingConnection();
    auto* handler = new ClientHandler(sock, this);

    Q_UNUSED(handler);
}


ClientHandler::ClientHandler(QAbstractSocket* sock, QObject* parent)
: QObject  (parent)
, m_socket (sock)
, m_state  (State::LoginAwaitName)
{
    m_socket->setParent(this);
    connect( m_socket, &QAbstractSocket::disconnected
           , this,     &QObject::deleteLater);

    connect( m_socket, &QAbstractSocket::readyRead
           , this,     &ClientHandler::gotData);

    m_socket->write("Enter your name: ");


    // sometimes data is ready before we connect signals, so we emit them
    // manually
    if (m_socket->isReadable())  this->gotData();
}


void ClientHandler::gotData()
{
    auto data = m_socket->readLine();
    if (data.isNull())  return;

    switch (m_state)
    {
        case State::LoginAwaitName:
            loginName(std::move(data));
            return;
        case State::LoginAwaitPass:
            loginPass(std::move(data));
            return;
        case State::RegAwaitPass:
            regPass(std::move(data));
            return;

        case State::UserAwaitCommand:
            userCommand(std::move(data));
            return;
        case State::UserAwaitTicket:
            userTicket(std::move(data));
            return;
        case State::UserAwaitExhangePartner:
            userExhangePartner(std::move(data));
            return;
        case State::UserAwaitAcceptName:
            userAcceptName(std::move(data));
            return;
        case State::UserAwaitAcceptConfirm:
            userAcceptConfirm(std::move(data));
            return;

        case State::AdminAwaitCommand:
            adminCommand(std::move(data));
            return;
        case State::AdminAwaitWinName:
            adminWinName(std::move(data));
            return;
        case State::AdminAwaitWinNumber:
            adminWinNumber(std::move(data));
            return;
    }

    // redo if we still have lines left
    if (m_socket->isReadable())  this->gotData();
}


void ClientHandler::loginName(QByteArray&& data)
{
    let name = QString::fromUtf8(data.trimmed());
    let db = store::connectDb();
    let mbUser = store::getUser(db, name);

    m_socket->write("Password: ");

    if (mbUser.has_value())
    {
        m_subject = *mbUser;
        m_state = State::LoginAwaitPass;
    }
    else
    {
        m_subject.name = name;
        m_state = State::RegAwaitPass;
    }
}

void ClientHandler::loginPass(QByteArray&& data)
{
    let pass = QString::fromUtf8(data.trimmed());

    if (pass != m_subject.password)
    {
        m_socket->write("Incorrect password\nEnter your name: ");
        m_state = State::LoginAwaitName;
        return;
    }

    if (m_subject.name == "admin")
    {
        auto gen = StringGenerator(m_subject.password);
        m_subject.password = gen.generate(32);
        let r = store::setUser(store::connectDb(), m_subject);
        if (not r)
        {
            m_socket->write("Database failure\n");
            m_socket->close();
            return;
        }
        let msg = "New password: '" + m_subject.password + "'\n";
        m_socket->write(msg.toUtf8());
        m_state = State::AdminAwaitCommand;
    }
    else
    {
        m_state = State::UserAwaitCommand;
        menuBanner();
    }
}

void ClientHandler::regPass(QByteArray&& data)
{
    let db = store::connectDb();
    m_subject.password = QString::fromUtf8(data.trimmed());
    let success = store::createUser(db, m_subject);
    if (not success)
    {
        m_socket->write("Failed to register."
                        " Try later with a different name.\n"
                       );
        m_socket->close();
    }
    else
    {
        m_state = State::UserAwaitCommand;
        menuBanner();
    }
}


void ClientHandler::userCommand(QByteArray&& data)
{
    reloadSubject();
    auto out = QDebug(m_socket);
    if (data == "buy\n")
    {
        out << "Enter the desired ticket:";
        m_state = State::UserAwaitTicket;
    }
    else if (data == "exchange\n")
    {
        out << "Enter your partner's name:";
        m_state = State::UserAwaitExhangePartner;
    }
    else if (data == "accept\n")
    {
        out << "Here's who wants to exchange with you:";
        for (let& name : m_subject.pendingTrades)  out << name;
        out << "\nSelect name to trade:";

        m_state = State::UserAwaitAcceptName;
    }
    else if (data == "show\n")
    {
        out << m_subject.ticket.toHex() << "\n>";
    }
    else if (data == "list\n")
    {
        let users = store::listUsers(store::connectDb());
        for (let& user : users)  out << user;
        out << "\n>";
    }
    else
    {
        out << "Bad command";
    }
}

void ClientHandler::userTicket(QByteArray&& data)
{
    reloadSubject();
    m_state = State::UserAwaitCommand;

    let words = data.trimmed().split(' ');
    if (words.length() < Ticket::DataSize)
    {
        m_socket->write("Ticket is 32 small numbers");
        return;
    }

    int index = 0;
    for (let& word : words)
    {
        if (index > Ticket::DataSize)  break;

        auto ok = true;
        let num = word.toInt(&ok) % 256;
        m_subject.ticket.data[index] = static_cast<qint8>(num);

        if (not ok)
        {
            m_socket->write("Bad number: " + word + "\n");
            m_subject.ticket.data[0] = 0;
            return;
        }

        index += 1;
    }
    store::setUser(store::connectDb(), m_subject);

    m_socket->write("Alright, you bought "
                   + m_subject.ticket.toHex().toUtf8() + "\n> ");
}

void ClientHandler::userExhangePartner(QByteArray&& data)
{
    let db = store::connectDb();
    let name = QString::fromUtf8(data.trimmed());
    let mbUser = store::getUser(db, name);

    if (not mbUser.has_value())
    {
        m_socket->write("User does not exist\n");
    }
    else
    {
        m_object = *mbUser;
        if (m_object.pendingTrades.contains(m_subject.name))
        {
            m_socket->write("Already awaiting reply from user\n");
        }
        else
        {
            m_object.pendingTrades.append(m_subject.name);
            let success = store::setUser(db, m_object);
            if (not success)  m_socket->write("Some failure\n");
            else  m_socket->write("Invitation sent, await user response\n");
        }
    }

    m_state = State::UserAwaitCommand;
}

void ClientHandler::userAcceptName(QByteArray&& data)
{
    let db = store::connectDb();
    let name = QString::fromUtf8(data.trimmed());
    let mbUser = store::getUser(db, name);
    if (not mbUser.has_value())
    {
        m_socket->write("Bad name\n");
        m_state = State::UserAwaitCommand;
    }
    else
    {
        m_object = *mbUser;
        m_socket->write("Are you sure you want to trade with "
                       + name.toUtf8() + "? (y/N)\n");
        m_state = State::UserAwaitAcceptConfirm;
    }
}

void ClientHandler::userAcceptConfirm(QByteArray&& data)
{
    reloadSubject();
    reloadObject();
    if (data.isEmpty() or data.at(0) != 'y')
    {
        m_socket->write("Aborted\n");
        m_state = State::UserAwaitCommand;
        return;
    }

    let db = store::connectDb();
    Ticket::swap(m_subject.ticket, m_object.ticket);
    m_subject.pendingTrades.removeOne(m_object.name);

    let s1 = store::setUser(db, m_subject);
    let s2 = store::setUser(db, m_object);
    if (not s1 or not s2)
    {
        m_socket->write("Bad thing happened\n");
        m_socket->close();
        return;
    }

    m_socket->write("Exchange completed!\n");
    m_state = State::UserAwaitCommand;
}


void ClientHandler::adminCommand(QByteArray&& data)
{
    auto out = QDebug(m_socket);
    if (data == "name\n")
    {
        out << "Enter the winner's name:";
        m_state = State::AdminAwaitWinName;
    }
    else if (data == "number\n")
    {
        out << "Enter the winning number:";
        m_state = State::AdminAwaitWinNumber;
    }
}

void ClientHandler::adminWinName(QByteArray&& data)
{
    auto out = QDebug(m_socket);
    let db = store::connectDb();
    let name = QString::fromUtf8(data.trimmed());
    let mbUser = store::getUser(db, name);

    if (not mbUser.has_value())
    {
        m_socket->write("User does not exist\n");
    }
    else
    {
        m_object = *mbUser;
        m_object.wonRecently = true;
        store::setUser(db, m_object);
        out << "User" << m_object.name
            << "with ticket" << m_object.ticket.toHex()
            << "has won\n>";
    }
    m_state = State::AdminAwaitCommand;
}

void ClientHandler::adminWinNumber(QByteArray&& data)
{
    let db = store::connectDb();
    let number = QString::fromUtf8(data.trimmed());
    let mbUser = store::getByTicket(db, number);

    if (not mbUser.has_value())
    {
        m_socket->write("Ticket does not exist\n");
    }
    else
    {
        m_object = *mbUser;
        m_object.wonRecently = true;
        store::setUser(db, m_object);
        m_socket->write(m_object.name.toUtf8() + " has won, yay\n");
    }
    m_state = State::AdminAwaitCommand;
}

void ClientHandler::menuBanner()
{
    m_socket->write(
        "Welcome to PYCCKOE /\\OTO!\n"
        "Buy and exchange your lottery tickets here to win valuable prizes!\n"
        "Commands:\n"
        "  buy - to buy a new ticket\n"
        "  exchange - to exchange your ticket with someone\n"
        "  accept - to accept an exchange\n"
        "  show - to remind you your ticket\n"
        "  list - to list all registered users\n"
    );
    if (m_subject.wonRecently)
    {
        m_socket->write("Your ticket has recently won!\n");
        m_subject.wonRecently = false;
    }
    m_socket->write("> ");
}


void ClientHandler::reloadSubject()
{
    let mbUser = store::getUser(store::connectDb(), m_subject.name);
    m_subject = *mbUser;
}
void ClientHandler::reloadObject()
{
    let mbUser = store::getUser(store::connectDb(), m_object.name);
    m_object = *mbUser;
}
