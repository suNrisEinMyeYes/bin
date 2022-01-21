#pragma once

#include <QString>
#include <random>

// Description: deterministic latin string generator

class StringGenerator
{
    std::mt19937 m_gen;
    std::uniform_int_distribution<std::uint_fast32_t> m_dis;

public:
    StringGenerator(const QString&);
    void reseed(const QString&);
    auto generate(size_t) -> QString;
};
