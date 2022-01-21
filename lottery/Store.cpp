#include "defines.h"

#include "Store.h"

#include <QDebug>
#include <QDir>
#include <QStandardPaths>
#include <cstring>
#include <stdexcept>


Ticket::Ticket()
{
    std::memset(data, 0, DataSize);
}
Ticket::Ticket(const QByteArray& ba)
{
    std::strncpy(reinterpret_cast<char*>(data), ba.constData(), DataSize);
}
Ticket::Ticket(const QString& str)
{
    std::strncpy(reinterpret_cast<char*>(data), str.toStdString().data(), DataSize);
}

void Ticket::qtRegister()
{
    qRegisterMetaType<Ticket>();
    QMetaType::registerConverter<QString,    Ticket>();
    QMetaType::registerConverter<QByteArray, Ticket>();
}

void Ticket::swap(Ticket& l, Ticket& r)
{
    qint8 data[Ticket::DataSize];
    std::memcpy(data,   l.data, DataSize);
    std::memcpy(l.data, r.data, DataSize);
    std::memcpy(r.data, data,   DataSize);
}

auto Ticket::toHex() const -> QString
{
    auto printableStr = QString("'");
    auto unprintStr = QString("X'");
    auto printable = true;
    //for (int i = 0; i < DataSize; ++i)
    for (let& val : data)
    {
        //let c = static_cast<unsigned int>(data[i]);
        let c = static_cast<unsigned int>(val);
        printable = printable and QChar::isPrint(c);
        if (printable)  printableStr.append(QChar(c));
        if (c < 16)  unprintStr.append("0");
        unprintStr.append(QString::number(c, 16));
    }
    printableStr.append("'");
    unprintStr.append("'");
    return printable ? printableStr : unprintStr;
}


namespace
{

constexpr char SqliteConnectionName[] = "LotteryDb";


[[ noreturn ]] auto throwSqlError(const QSqlError& err) -> void
{
    throw std::runtime_error(err.text().toStdString());
}

// helper function to avoid writing multiple ifs and throws
inline auto throwDbErrWhen(bool condition, const QSqlDatabase& db) -> void
{
    if (condition)  throwSqlError(db.lastError());
}
// execute a query and throw if there was an error
inline auto tryExecute(QSqlQuery& query) -> QSqlQuery&
{
    let success = query.exec();
    if (not success and query.lastError().isValid())
    {
        throwSqlError(query.lastError());
    }
    return query;
}
inline auto tryExecute(QSqlQuery& query, const QString& text) -> QSqlQuery&
{
    query.prepare(text);
    return tryExecute(query);
}


auto createQtDatabase(const QString& hostname) -> QSqlDatabase
{
    auto db = QSqlDatabase::addDatabase("QMYSQL", SqliteConnectionName);
    db.setHostName(hostname);
    db.setPort(3306);
    db.setDatabaseName("olegdb");
    db.setUserName("oleg");
    db.setPassword("oleg_2874c71881c3682f215be2f23e8173c4");

    throwDbErrWhen(not db.open(), db);

    return db;
}

auto initDbTables(QSqlDatabase& db) -> QSqlDatabase&
{
    let tables = db.tables();
    if (    tables.contains("users")
        and tables.contains("trades")
        and tables.contains("trades_temp")
       )
    {
        return db;
    }

    auto q = QSqlQuery(db);
    tryExecute(q, "create table if not exists users "
                  "( rowid        integer primary key auto_increment"
                  ", name         text not null"
                  ", password     text not null"
                  ", won_recently integer"
                  ", ticket       blob"
                  ");"
              );
    tryExecute(q, "create table if not exists trades "
                  "( origin integer"
                  ", target integer"
                  ", foreign key(origin) references users(rowid)"
                  ", foreign key(target) references users(rowid)"
                  ", unique (origin, target)"
                  ");"
              );
    tryExecute(q, "create table if not exists trades_temp "
                  "( rowid  integer primary key auto_increment"
                  ", origin text"
                  ", target text"
                  ");"
              );
    tryExecute(q, "insert into users (name, password) values"
                  "('admin', 'ZVwXtuORgXLfaLtBIqqDwCuD4MthWHTS');"
              );
    qDebug() << "created tables";

    return db;
}

} // namespace


namespace store
{

auto initDb(const QString& hostname) -> QSqlDatabase
{
    auto&& db = createQtDatabase(hostname);
    return initDbTables(db);
}

auto connectDb() -> QSqlDatabase
{
    let db = QSqlDatabase::database(SqliteConnectionName, true);
    throwDbErrWhen(not db.isOpen(), db);
    return db;
}

auto getUser(const QSqlDatabase& db, const QString& name)
    -> std::optional<User>
{
    auto query = QSqlQuery(db);
    try
    {
        query.prepare("select name, password, won_recently, ticket"
                      " from users where name = ?");
        query.addBindValue(name);
        tryExecute(query);

        if (not query.next())  return {};

        User user
            { query.value(0).toString()
            , query.value(1).toString()
            , query.value(2).toBool()
            , {}
            , query.value(3).value<Ticket>()
            };

        query.prepare("select o.name from trades"
                      " join users o on o.rowid = origin"
                      " join users t on t.rowid = target"
                      " where t.name = ?"
                     );
        query.addBindValue(name);
        tryExecute(query);
        while (query.next())
        {
            user.pendingTrades.append(query.value(0).toString());
        }

        return {user};
    }
    catch (std::exception& e)
    {
        qDebug() << e.what();
        return {};
    }
}

auto setUser(const QSqlDatabase& db, const User& user) -> bool
{
    auto query = QSqlQuery(db);
    try
    {
        query.prepare(
            QString("update users set"
                    " name = ?"
                    ",password = ?"
                    ",won_recently = ?"
                    ",ticket = %1"
                    " where name = ?"
                   ).arg(user.ticket.toHex())
        );
        query.addBindValue(user.name);
        query.addBindValue(user.password);
        query.addBindValue(user.wonRecently);
        query.addBindValue(user.name);
        tryExecute(query);

        query.prepare("delete trades from trades"
                      " join users on target = rowid where name = ?"
                     );
        query.addBindValue(user.name);
        tryExecute(query);

        if (user.pendingTrades.isEmpty())  return true;
        auto insertReqs = QString("insert into trades_temp (origin, target) values ");
        for (let& originName : user.pendingTrades)
        {
            // По первой задумке в этом сервисе должны были быть sql-инъекции,
            // но я передумал когда сам не смог их засплойтить. Это остаток той
            // эры, который я не знаю, как по нормальному переписать. Если вы
            // его таки смоги красиво переписать или даже запавнить,
            // расскажите мне как.
            // Кстати, вот эта гимнастика с trades_temp здесь потому что в mysql TEXT
            // не может быть primary key.
            auto fmt = QString("('%1', '%2'),");
            insertReqs.append(fmt.arg(originName, user.name));
        }
        insertReqs.chop(1); // the comma
        tryExecute(query, insertReqs);
        tryExecute(query, "insert into trades (origin, target)"
                          " select u1.rowid, u2.rowid from trades_temp"
                          " join users u1 on u1.name = origin"
                          " join users u2 on u2.name = target"
                  );
        tryExecute(query, "delete from trades_temp");

        return true;
    }
    catch (std::exception& e)
    {
        qDebug() << e.what();
        return false;
    }
}

auto createUser(const QSqlDatabase& db, const User& user) -> bool
{
    try
    {
        auto query = QSqlQuery(db);
        query.prepare(
            "insert into users (name, password)"
            " values (?, ?)"
        );
        query.addBindValue(user.name);
        query.addBindValue(user.password);
        tryExecute(query);
        return true;
    }
    catch (std::exception& e)
    {
        qDebug() << e.what();
        return {};
    }
}

auto getByTicket(const QSqlDatabase& db, const QString& ticket)
    -> std::optional<User>
{
    auto query = QSqlQuery(db);
    query.prepare("select name from users where ticket = ?");
    query.addBindValue(ticket);
    query.exec();

    if (not query.next())  return {};
    let name = query.value(0).toString();
    return getUser(db, name);
}

auto listUsers(const QSqlDatabase& db) -> QVector<QString>
{
    auto query = QSqlQuery(db);
    query.prepare("select name from users");
    query.exec();

    auto res = QVector<QString>();
    while (query.next())
    {
        res.append(query.value(0).toString());
    }
    return res;
}

} // namespace store
