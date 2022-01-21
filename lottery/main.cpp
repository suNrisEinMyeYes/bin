#include <QCoreApplication>

#include "Server.h"
#include "Store.h"

auto main(int argc, char *argv[]) -> int
{
    auto app = QCoreApplication(argc, argv);

    Ticket::qtRegister();
    store::initDb("mysql");

    auto server = Server();
    constexpr qint16 Port = 5001;
    server.listen(QHostAddress::Any, Port);

    return app.exec();
}
