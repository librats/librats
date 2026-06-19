#include <gtest/gtest.h>

#include "node/node.h"
#include "util/fs.h"

#include <string>

using namespace librats;

namespace {

NodeConfig persistent_config(const std::string& dir) {
    NodeConfig c;
    c.enable_listen = false;     // identity only; no networking needed
    c.data_dir = dir;
    return c;
}

std::string id_of(Node& n) { return n.local_id().to_hex(); }

} // namespace

// A node with a data_dir keeps the same self-certifying PeerId across restarts.
TEST(PersistenceTest, IdentityStableAcrossRestart) {
    const std::string dir = "rats_test_identity";
    delete_directory(dir.c_str());  // start clean

    std::string first, second;
    { Node n(persistent_config(dir)); first = id_of(n); }   // generates + saves
    { Node n(persistent_config(dir)); second = id_of(n); }  // loads the same key

    EXPECT_EQ(first, second);
    EXPECT_EQ(first.size(), 64u);
    EXPECT_TRUE(file_exists(combine_paths(dir, "identity.key")));

    delete_directory(dir.c_str());
}

// Without a data_dir each node gets a fresh random identity.
TEST(PersistenceTest, EphemeralIdentitiesDiffer) {
    NodeConfig c; c.enable_listen = false;  // data_dir empty
    Node a(c);
    Node b(c);
    EXPECT_NE(a.local_id(), b.local_id());
}

// A corrupt key file is ignored and a fresh identity is generated + saved.
TEST(PersistenceTest, RegeneratesOnCorruptKey) {
    const std::string dir = "rats_test_identity_corrupt";
    delete_directory(dir.c_str());
    create_directories(dir.c_str());
    const std::string key = combine_paths(dir, "identity.key");
    const char junk[] = "not a key";
    ASSERT_TRUE(create_file_binary(key.c_str(), junk, sizeof(junk)));

    std::string regenerated;
    { Node n(persistent_config(dir)); regenerated = id_of(n); }
    { Node n(persistent_config(dir)); EXPECT_EQ(regenerated, id_of(n)); }  // now stable

    delete_directory(dir.c_str());
}
