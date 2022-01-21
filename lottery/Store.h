#pragma once

#include <optional>
#include <QByteArray>
#include <QVector>
#include <QtSql>

// Description: representations of domain data: users and lottery tickets

struct Ticket
{
    static constexpr int DataSize = 32;
    qint8 data[DataSize];

    Ticket();
    Ticket(const QByteArray&);
    Ticket(const QString&);
    auto toHex() const -> QString;

    static void swap(Ticket&, Ticket&);
    static void qtRegister();
};
Q_DECLARE_METATYPE(Ticket);

struct User
{
    QString          name;
    QString          password;
    bool             wonRecently = false;
    QVector<QString> pendingTrades;
    Ticket           ticket;
};


namespace store
{

constexpr char DefaultDbHost[] = "localhost";

auto initDb(const QString& host = DefaultDbHost) -> QSqlDatabase;
auto connectDb() -> QSqlDatabase;

auto getUser(const QSqlDatabase&, const QString&) -> std::optional<User>;
auto setUser(const QSqlDatabase&, const User&) -> bool;
auto createUser(const QSqlDatabase&, const User&) -> bool;
auto getByTicket(const QSqlDatabase&, const QString&) -> std::optional<User>;
auto listUsers(const QSqlDatabase&) -> QVector<QString>;

} // namespace store
