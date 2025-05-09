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
  // print "start init tatbles"
  std::cout << "start init tables" << std::endl;

  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // create voter table
  std::string create_voter_query = "CREATE TABLE IF NOT EXISTS voter("
                                   "id TEXT PRIMARY KEY NOT NULL, "
                                   "value TEXT NOT NULL);";
  char *err;
  int exit = sqlite3_exec(this->db, create_voter_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }
 
  /* 
   * CHANGE: Modified voter table schema
   * - Replaced specific columns for individual fields with a single 'value' column
   * - This change allows storing serialized voter objects instead of individual fields
   */

  std::string create_vote_query = "CREATE TABLE IF NOT EXISTS vote("
                                  "vote TEXT PRIMARY KEY  NOT NULL, "
                                  "value TEXT NOT NULL);";
  exit = sqlite3_exec(this->db, create_vote_query.c_str(), NULL, 0, &err);
  if (exit != SQLITE_OK) {
    std::cerr << "Error creating table: " << err << std::endl;
  } else {
    std::cout << "Table created successfully" << std::endl;
  }

  /* 
   * CHANGE: Modified partial_decryption table schema
   * - Simplified to use a single 'value' column instead of multiple fields
   * - Allows storing serialized partial_decryption objects
   */

  std::string create_partial_decryption_query =
      "CREATE TABLE IF NOT EXISTS partial_decryption("
      "arbiter_id TEXT PRIMARY KEY NOT NULL, "
      "value TEXT NOT NULL);";
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

  std::string find_query = "SELECT id, val"
                           "FROM voter WHERE id = ?";

  /* 
   * CHANGE: Updated find_voter query
   * - Changed the SQL to match new schema with 'value' field
   * - Old query was selecting specific fields (id, registrar_signature)
   * - New query gets id and serialized value column
   */
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
        // voter.registrar_signature =
        //     string_to_integer(std::string((const char *)raw_result, num_bytes));
        std::string data = std::string((const char *)raw_result, num_bytes);
        std::vector<unsigned char> data_vec = str2chvec(data);
        voter.deserialize(data_vec);
        /* 
         * CHANGE: Updated voter deserialization
         * - Replaced direct field assignment with full deserialization
         * - Now converts string to byte vector and uses deserialize method
         * - This handles the complete voter object instead of individual fields
         */
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

  std::string insert_query = "INSERT INTO voter(id, value) "
                             "VALUES(?, ?);";

  // // Serialize voter fields.
  // std::string registrar_signature_str =
  //     integer_to_string(voter.registrar_signature);

  // use deserialize function to convert to string for voter.voter
  std::vector<unsigned char> voter_data;
  voter.serialize(voter_data);
  std::string voter_data_str = chvec2str(voter_data);

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, voter.id.c_str(), voter.id.length(),
                    SQLITE_STATIC);
  // sqlite3_bind_blob(stmt, 2, registrar_signature_str.c_str(),
  //                   registrar_signature_str.length(), SQLITE_STATIC);

  sqlite3_bind_blob(stmt, 2, voter_data_str.c_str(), voter_data_str.length(),
                  SQLITE_STATIC);

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

  // std::string find_query =
  //     "SELECT vote, zkp, unblinded_signature, tallyer_signature FROM vote";

  std::string find_query =
    "SELECT vote, value FROM vote";

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
        vote.deserialize(data);
        /* 
         * CHANGE: Updated vote deserialization
         * - Now deserializes complete vote object from value field
         * - Replaces handling multiple individual fields separately
         */
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

  // std::string find_query = "SELECT vote, zkp, unblinded_signature, "
  //                          "tallyer_signature FROM vote WHERE vote = ?";

  std::string find_query = "SELECT vote, value FROM vote WHERE vote = ?";

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
        // vote.zkp.deserialize(data);
        vote.deserialize(data);
        /* 
         * CHANGE: Updated vote deserialization 
         * - Now deserializes the entire vote object from value column
         * - Replaced specific field deserialization (zkp) with complete object
         */
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
  // print debugging message here
  // std::cout << "[Debug] inserting vote" << std::endl;
  // Lock db driver.
  std::unique_lock<std::mutex> lck(this->mtx);

  // std::string insert_query = "INSERT INTO vote(vote, zkp, unblinded_signature, "
  //                            "tallyer_signature) VALUES(?, ?, ?, ?);";


  std::string insert_query = "INSERT INTO vote(vote,value) VALUES(?, ?);";
  /* 
   * CHANGE: Updated insert_vote query
   * - Changed from inserting multiple fields to just vote and value columns
   * - Simplified to match new schema with serialized objects
   * - Removed parameters for zkp, unblinded_signature, tallyer_signature
   */

  // Serialize vote fields.
  std::vector<unsigned char> vote_data;
  vote.serialize(vote_data);
  std::string vote_str = chvec2str(vote_data);

  // std::vector<unsigned char> zkp_data;
  // vote.zkp.serialize(zkp_data);
  // std::string zkp_str = chvec2str(zkp_data);

  // std::string unblinded_signature_str =
  //     CryptoPP::IntToString(vote.unblinded_signature);

  std::string tallyer_signature_str = vote.tallyer_signature;

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, vote_str.c_str(), vote_str.length(),
                    SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, vote_str.c_str(), vote_str.length(),
                    SQLITE_STATIC);
  // sqlite3_bind_blob(stmt, 2, zkp_str.c_str(), zkp_str.length(), SQLITE_STATIC);
  // sqlite3_bind_blob(stmt, 3, unblinded_signature_str.c_str(),
  //                   unblinded_signature_str.length(), SQLITE_STATIC);
  // sqlite3_bind_blob(stmt, 4, tallyer_signature_str.c_str(),
  //                   tallyer_signature_str.length(), SQLITE_STATIC);

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

  std::string find_query = "SELECT arbiter_id, value FROM partial_decryption";

  /* 
   * CHANGE: Updated all_partial_decryptions query
   * - Changed to select arbiter_id and value columns
   * - Simplified to match new schema with serialized objects
   */

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
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.deserialize(data);
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
      "SELECT arbiter_id, value FROM "
      "partial_decryption WHERE arbiter_id = ?";

  /* 
   * CHANGE: Updated find_partial_decryption query
   * - Changed to select arbiter_id and value columns
   * - Simplified to match new schema with serialized objects
   */

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
        // partial_decryption.arbiter_id =
        //     std::string((const char *)raw_result, num_bytes);
        data = str2chvec(std::string((const char *)raw_result, num_bytes));
        partial_decryption.deserialize(data);
        /* 
         * CHANGE: Updated partial_decryption deserialization
         * - Now deserializes complete object instead of setting field directly
         * - Converts string to byte vector and uses deserialize method
         * - Replaces direct assignment of arbiter_id field
         */
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
      "INSERT OR REPLACE INTO partial_decryption(arbiter_id, value) VALUES(?, ?);";

  // Serialize pd fields.
  std::vector<unsigned char> partial_decryption_data;
  partial_decryption.serialize(partial_decryption_data);
  std::string partial_decryption_str = chvec2str(partial_decryption_data);

  /* 
   * CHANGE: Updated partial_decryption serialization
   * - Now serializes complete object to byte vector then string
   * - Replaces serializing individual fields separately
   */


  // std::vector<unsigned char> zkp_data;
  // partial_decryption.zkp.serialize(zkp_data);
  // std::string zkp_str = chvec2str(zkp_data);

  // Prepare statement.
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(this->db, insert_query.c_str(), insert_query.length(),
                     &stmt, nullptr);
  sqlite3_bind_blob(stmt, 1, partial_decryption_str.c_str(),
                    partial_decryption_str.length(), SQLITE_STATIC);
  sqlite3_bind_blob(stmt, 2, partial_decryption_str.c_str(),
                    partial_decryption_str.length(), SQLITE_STATIC);
  // sqlite3_bind_blob(stmt, 3, partial_decryption_str.c_str(),
  //                   partial_decryption_str.length(), SQLITE_STATIC);
  // sqlite3_bind_blob(stmt, 4, zkp_str.c_str(), zkp_str.length(), SQLITE_STATIC);

  /* 
   * CHANGE: Updated parameter binding
   * - Now binds serialized data to both arbiter_id and value columns
   * - Simplified from binding multiple fields to binding just serialized object twice
   * - Removed binding for unnecessary fields
   */

  // Run and return.
  sqlite3_step(stmt);
  int exit = sqlite3_finalize(stmt);
  if (exit != SQLITE_OK) {
    std::cerr << "Error inserting partial_decryption " << std::endl;
  }

  return partial_decryption;
}