#include <fstream>
#include <iostream>
#include <stdexcept>

#include "../../include-shared/util.hpp"
#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"

// ================================================
// INITIALIZATION
// ================================================

/**
 * Initialize DBDriver.
 */
DBDriver::DBDriver() {}

/**
 * Open a particular db file.
 */
int DBDriver::open(std::string dbpath) {
  return sqlite3_open(dbpath.c_str(), &this->db);
}

/**
 * Close db.
 */
int DBDriver::close() { return sqlite3_close(this->db); }

/**
 * Initialize tables.
 */
void DBDriver::init_tables() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // create voter table
  std::string create_voter_query = "CREATE TABLE IF NOT EXISTS voter("
                                   "id TEXT PRIMARY KEY NOT NULL, "
                                   "registrar_signature TEXT NOT NULL);";
  char *err;
  int exit = sqlite3_exec(this->db, create_voter_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }

  // create vote table
  std::string create_vote_query = "CREATE TABLE IF NOT EXISTS vote("
                                  "vote TEXT PRIMARY KEY  NOT NULL, "
                                  "zkp TEXT NOT NULL, "
                                  "unblinded_signature TEXT NOT NULL,"
                                  "tallyer_signature TEXT NOT NULL);";
  exit = sqlite3_exec(this->db, create_vote_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }

  // create partial_decryption table
  std::string create_partial_decryption_query =
      "CREATE TABLE IF NOT EXISTS partial_decryption("
      "arbiter_id TEXT PRIMARY KEY NOT NULL, "
      "arbiter_vk_path TEXT NOT NULL, "
      "partial_decryption TEXT NOT NULL, "
      "zkp TEXT NOT NULL);";
  exit = sqlite3_exec(this->db, create_partial_decryption_query.c_str(), NULL,
                      0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }
}

/**
 * Reset tables by dropping all.
 */
void DBDriver::reset_tables() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // Get all table names
  std::vector<std::string> table_names;
  table_names.push_back("voter");
  table_names.push_back("vote");
  table_names.push_back("partial_decryption");

  sqlite3_stmt *stmt;
  // For each table, drop it
  for (std::string table : table_names) {
    std::string delete_query = "DELETE FROM " + table;
    sqlite3_prepare_v2(this->db, delete_query.c_str(), delete_query.length(),
                       &stmt, nullptr);
    char *err;
    int exit = sqlite3_exec(this->db, delete_query.c_str(), NULL, 0, &err);
    if (exit != SQLITE_OK) {
      std::cerr << "Error dropping table: " << err << std::endl;
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error resetting tables" << std::endl;
  }
}

// ================================================
// VOTER
// ================================================

/**
 * Find the given voter. Returns an empty voter if none was found.
 */
VoterRow DBDriver::find_voter(std::string id) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query = "SELECT id, registrar_signature "
                           "FROM voter WHERE id = ?";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, id.c_str(), id.length(), SQLITE_STATIC);

  // Retreive voter.
  VoterRow voter;
  std::string verification_key_str;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      switch (colIndex) {
      case 0:
        voter.id = std::string((const char *)raw_result, num_bytes);
        ;
        break;
      case 1:
        voter.registrar_signature =
            string_to_integer(std::string((const char *)raw_result, num_bytes));
        break;
      }
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding voter " << std::endl;
  }
  return voter;
}

/**
 * Insert the given voter; prints an error if violated a primary key constraint.
 */
VoterRow DBDriver::insert_voter(VoterRow voter) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string insert_query = "INSERT INTO voter(id, registrar_signature) "
                             "VALUES(?, ?);";

  // Serialize voter fields.
  std::string registrar_signature_str =
      integer_to_string(voter.registrar_signature);

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, voter.id.c_str(), voter.id.length(),
                    SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, registrar_signature_str.c_str(),
                    registrar_signature_str.length(), SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error inserting voter " << std::endl;
    // informative error
    std::cerr << "Error inserting voter " << voter.id << std::endl;
    std::cerr << "Error code: " << exit << std::endl;
  }
  return voter;
}

// ================================================
// VOTE
// ================================================

/**
 * Return all votes.
 */
std::vector<VoteRow> DBDriver::all_votes() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query =
      "SELECT vote, zkp, unblinded_signature, tallyer_signature FROM vote";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);

  // Retreive vote.
  std::vector<VoteRow> res;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    VoteRow vote;
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      std::vector<unsigned char> data;
      switch (colIndex) {
      case 0:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.vote.deserialize(data);
        break;
      case 1:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.zkp.deserialize(data);
        break;
      case 2:
        vote.unblinded_signature =
            CryptoPP::Integer(std::string((const char *)raw_result).c_str());
        break;
      case 3:
        vote.tallyer_signature =
            std::string((const char *)raw_result, num_bytes);
        break;
      }
    }
    res.push_back(vote);
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding vote " << std::endl;
  }
  return res;
}

/**
 * Find the given vote. Returns an empty vote if none was found.
 */
VoteRow DBDriver::find_vote(Vote_Ciphertext vote_s) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query = "SELECT vote, zkp, unblinded_signature, "
                           "tallyer_signature FROM vote WHERE vote = ?";

  // Serialize vote struct.
  std::vector<unsigned char> vote_data;
  vote_s.serialize(vote_data);
  std::string vote_str = chvec2str(vote_data);

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, vote_str.c_str(), vote_str.length(),
                    SQLITE_STATIC);

  // Retreive vote.
  VoteRow vote;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      std::vector<unsigned char> data;
      switch (colIndex) {
      case 0:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.vote.deserialize(data);
        break;
      case 1:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        vote.zkp.deserialize(data);
        break;
      case 2:
        vote.unblinded_signature =
            CryptoPP::Integer(std::string((const char *)raw_result).c_str());
        break;
      case 3:
        vote.tallyer_signature =
            std::string((const char *)raw_result, num_bytes);
        break;
      }
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding vote " << std::endl;
  }
  return vote;
}

/**
 * Insert the given vote; prints an error if violated a primary key constraint.
 */
VoteRow DBDriver::insert_vote(VoteRow vote) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string insert_query = "INSERT INTO vote(vote, zkp, unblinded_signature, "
                             "tallyer_signature) VALUES(?, ?, ?, ?);";

  // Serialize vote fields.
  std::vector<unsigned char> vote_data;
  vote.vote.serialize(vote_data);
  std::string vote_str = chvec2str(vote_data);

  std::vector<unsigned char> zkp_data;
  vote.zkp.serialize(zkp_data);
  std::string zkp_str = chvec2str(zkp_data);

  std::string unblinded_signature_str =
      CryptoPP::IntToString(vote.unblinded_signature);

  std::string tallyer_signature_str = vote.tallyer_signature;

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, vote_str.c_str(), vote_str.length(),
                    SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, zkp_str.c_str(), zkp_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, unblinded_signature_str.c_str(),
                    unblinded_signature_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 4, tallyer_signature_str.c_str(),
                    tallyer_signature_str.length(), SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error inserting vote " << std::endl;
  }
  return vote;
}

/**
 * Returns if vote is in database
 */
bool DBDriver::vote_exists(Vote_Ciphertext vote) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query = "SELECT 1 FROM vote WHERE vote = ?";

  // Serialize vote.
  std::vector<unsigned char> vote_data;
  vote.serialize(vote_data);
  std::string vote_str = chvec2str(vote_data);

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, vote_str.c_str(), vote_str.length(),
                    SQLITE_STATIC);

  // Check if exists.
  bool result;
  int rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    result = true;
  } else if (rc == SQLITE_DONE) {
    result = false;
  } else {
    std::cerr << "Error finding vote " << std::endl;
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding vote " << std::endl;
  }
  return result;
}

// ================================================
// PARTIAL_DECRYPTIONS
// ================================================

/**
 * Return all partial decryptions.
 */
std::vector<PartialDecryptionRow>
DBDriver::DBDriver::all_partial_decryptions() {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query = "SELECT arbiter_id, arbiter_vk_path, "
                           "partial_decryption, zkp FROM partial_decryption";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);

  // Retreive partial_decryption.
  std::vector<PartialDecryptionRow> res;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    PartialDecryptionRow partial_decryption;
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      std::vector<unsigned char> data;
      switch (colIndex) {
      case 0:
        partial_decryption.arbiter_id =
            std::string((const char *)raw_result, num_bytes);
        break;
      case 1:
        partial_decryption.arbiter_vk_path =
            std::string((const char *)raw_result, num_bytes);
        break;
      case 2:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.dec.deserialize(data);
        break;
      case 3:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.zkp.deserialize(data);
        break;
      }
    }
    res.push_back(partial_decryption);
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding partial_decryption " << std::endl;
  }
  return res;
}

/**
 * Find the given partial_decryption. Returns an empty partial_decryption if
 * none was found.
 */
PartialDecryptionRow DBDriver::find_partial_decryption(std::string arbiter_id) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string find_query =
      "SELECT arbiter_id, arbiter_vk_path, partial_decryption, zkp FROM "
      "partial_decryption WHERE arbiter_id = ?";

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, find_query.c_str(), find_query.length(), &stmt,
                     nullptr);
  sqlite3_bind_blob(stmt, 1, arbiter_id.c_str(), arbiter_id.length(),
                    SQLITE_STATIC);

  // Retreive partial_decryption.
  PartialDecryptionRow partial_decryption;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); colIndex++) {
      const void *raw_result = sqlite3_column_blob(stmt, colIndex);
      int num_bytes = sqlite3_column_bytes(stmt, colIndex);
      std::vector<unsigned char> data;
      switch (colIndex) {
      case 0:
        partial_decryption.arbiter_id =
            std::string((const char *)raw_result, num_bytes);
        break;
      case 1:
        partial_decryption.arbiter_vk_path =
            std::string((const char *)raw_result, num_bytes);
        break;
      case 2:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.dec.deserialize(data);
        break;
      case 3:
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.zkp.deserialize(data);
        break;
      }
    }
  }

  // Finalize and return.
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error finding partial_decryption " << std::endl;
  }
  return partial_decryption;
}

/**
 * Insert the given partial_decryption; prints an error if violated a primary
 * key constraint.
 */
PartialDecryptionRow
DBDriver::insert_partial_decryption(PartialDecryptionRow partial_decryption) {
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  std::string insert_query =
      "INSERT OR REPLACE INTO partial_decryption(arbiter_id, "
      "arbiter_vk_path, partial_decryption, zkp) VALUES(?, ?, ?, ?);";

  // Serialize pd fields.
  std::vector<unsigned char> partial_decryption_data;
  partial_decryption.dec.serialize(partial_decryption_data);
  std::string partial_decryption_str = chvec2str(partial_decryption_data);

  std::vector<unsigned char> zkp_data;
  partial_decryption.zkp.serialize(zkp_data);
  std::string zkp_str = chvec2str(zkp_data);

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, partial_decryption.arbiter_id.c_str(),
                    partial_decryption.arbiter_id.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, partial_decryption.arbiter_vk_path.c_str(),
                    partial_decryption.arbiter_vk_path.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 3, partial_decryption_str.c_str(),
                    partial_decryption_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 4, zkp_str.c_str(), zkp_str.length(), SQLITE_STATIC);

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error inserting partial_decryption " << std::endl;
  }
  return partial_decryption;
}
