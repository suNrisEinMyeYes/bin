#include "defines.h"
#include "StringGenerator.h"

using fi32 = std::uint_fast32_t;


StringGenerator::StringGenerator(const QString& seed)
: m_dis ('0', 'z')
{
    reseed(seed);
}


void StringGenerator::reseed(const QString& str)
{
    for (let& unicode : str)
    {
        let mixer = m_dis(m_gen);
        let c = static_cast<fi32>(unicode.toLatin1());
        m_gen.seed(mixer + c);
    }
}


auto StringGenerator::generate(size_t length) -> QString
{
    auto str = QString();
    for (size_t i = 0; i < length; ++i)
    {
        let c = static_cast<unsigned char>(m_dis(m_gen));
        str.append(c);
    }
    return str;
}
