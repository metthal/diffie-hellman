#pragma once

#include <type_traits>

template <typename... Ts>
struct IsOneOf : std::false_type {};

template <typename SearchedT, typename... Ts>
struct IsOneOf<SearchedT, SearchedT, Ts...> : std::true_type {};

template <typename SearchedT, typename T, typename... Ts>
struct IsOneOf<SearchedT, T, Ts...> : IsOneOf<SearchedT, Ts...> {};
