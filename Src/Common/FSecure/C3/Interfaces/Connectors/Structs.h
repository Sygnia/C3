#pragma once
#include "StdAfx.h"
#include "Common/json/json.hpp"

namespace FSecure::C3::Interfaces::Connectors::Messages
{
    class ApolloIPCChunked {
        //private: 

    public:
        std::string id;
        int message_type;
        int chunk_number;
        int total_chunks;
        std::string data;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(ApolloIPCChunked, id, message_type, chunk_number, total_chunks, data);

        int GetChunkNumber()
        {
            return this->chunk_number;
        }
        int GetChunkSize()
        {
            return this->data.length();
        }
        int GetTotalChunks()
        {
            return this->total_chunks;
        }
    };

    template<typename T>
    class ChunkMessageEventArgs
    {
    public:
        ChunkMessageEventArgs(const std::vector<T>& messages)
            : _messages(messages)
        {}

        const std::vector<T>& GetMessages() const
        {
            return _messages;
        }

    private:
        std::vector<T> _messages;
    };

    template<typename T>
    class ChunkedMessageStore
    {
    public:
        using EventHandler = std::function<void(ChunkedMessageStore<T>*, const ChunkMessageEventArgs<T>&)>;
        using EventHandler2 = std::function<void(ChunkMessageEventArgs<T>&)>;

        ChunkedMessageStore() = default;
        /*~ChunkedMessageStore() {
            delete[] _messages;
        }*/

        // Move constructor
        ChunkedMessageStore(ChunkedMessageStore&& other) noexcept
            : _messages(std::move(other._messages)), _currentCount(other._currentCount) {
        }
        // Disable copy constructor
        ChunkedMessageStore(const ChunkedMessageStore&) = delete;
        // Disable copy assignment operator
        ChunkedMessageStore& operator=(const ChunkedMessageStore&) = delete;

        // Move assignment operator
        ChunkedMessageStore& operator=(ChunkedMessageStore&& other) noexcept {
            if (this != &other) {
                _messages = std::move(other._messages);
                _currentCount = other._currentCount;
            }
            return *this;
        }


        void OnMessageComplete()
        {
            if (MessageComplete)
            {
                ChunkMessageEventArgs<T> args(_messages);
                MessageComplete(args);
            }
        }

        void AddMessage(T& message)
        {
            std::lock_guard<std::mutex> lock(_lock);

            if (_messages.empty())
            {
                _messages.resize(message.GetTotalChunks());
            }

            _messages[message.GetChunkNumber() - 1] = message;
            _currentCount += 1;

            if (_currentCount == message.GetTotalChunks())
            {
                OnMessageComplete();
            }
            else if (ChunkAdd)
            {
                ChunkMessageEventArgs<T> args({ message });
                ChunkAdd(this, args);
            }
        }

        std::vector<T> GetMessages() const
        {
            std::lock_guard<std::mutex> lock(_lock);
            return _messages;
        }

        EventHandler ChunkAdd;
        EventHandler2 MessageComplete;

    private:
        std::vector<T> _messages;
        std::mutex _lock;
        int _currentCount = 0;
    };

    template<typename Key, typename Value>
    class ConcurrentDictionary {
    private:
        std::unordered_map<Key, Value> dictionary;
        mutable std::mutex mutex;

    public:
        void Add(const Key& key, const Value& value) {
            std::lock_guard<std::mutex> lock(mutex);
            dictionary[key] = value;
        }

        void Remove(const Key& key) {
            std::lock_guard<std::mutex> lock(mutex);
            dictionary.erase(key);
        }
        bool ContainsKey(const Key& key) const {
            std::lock_guard<std::mutex> lock(mutex);
            return dictionary.find(key) != dictionary.end();
        }

        bool TryGetValue(const Key& key, Value& value) {
            std::lock_guard<std::mutex> lock(mutex);
            auto it = dictionary.find(key);
            if (it != dictionary.end()) {
                value = it->second;
                return true;
            }
            return false;
        }
        Value& GetValue(const Key& key) {
            std::lock_guard<std::mutex> lock(mutex);
            return dictionary[key];
        }

        void Clear() {
            std::lock_guard<std::mutex> lock(mutex);
            dictionary.clear();
        }

        Value& operator[](const Key& key) {
            std::lock_guard<std::mutex> lock(mutex);
            return dictionary[key];
        }

        const Value& operator[](const Key& key) const {
            std::lock_guard<std::mutex> lock(mutex);
            return dictionary[key];
        }

        // Move constructor
        ConcurrentDictionary() = default;
        ConcurrentDictionary(ConcurrentDictionary&& other) noexcept
            : dictionary(std::move(other.dictionary)) {
        }

        // Move assignment operator
        ConcurrentDictionary& operator=(ConcurrentDictionary&& other) noexcept {
            if (this != &other) {
                dictionary = std::move(other.dictionary);
            }
            return *this;
        }

        // Disable copy constructor
        ConcurrentDictionary(const ConcurrentDictionary&) = delete;

        // Disable copy assignment operator
        ConcurrentDictionary& operator=(const ConcurrentDictionary&) = delete;
    };
}