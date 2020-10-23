#include <iostream>
#include <string>
#include <vector>
#include <sstream>

static std::string WHITE_LIST [] = {
            "ABS","ADD","ALTER","ALL","AND","ANY","AS","ASC","BACKUP","BEFORE","BEGIN","BETWEEN","BY","CALL","CASE","CAST","CHECK","COLLATE","COLUMN","COUNT","COMMIT","CONSTRAINT","CREATE","CROSS","CURRENT","CURSOR",
            "DATABASE","DEALLOCATE","DECLARE","DESCRIBE","DEFAULT","DELETE","DESC","DISTINCT","DROP","ELSE","END","ESCAPE","EXEC","EXECUTE","EXISTS","FALSE","FETCH","FOREIGN","FROM","FULL","FUNCTION",
            "GET","GLOBAL","GRANT","GROUP","HAVING","HOLD","IN","INTO","INDEX","INNER","INSERT","IS","JOIN",
            "LEFT","LIKE","LIMIT","MATCH","MODIFIES","NEW","NEXT","NO","NOT","NULL","OR","ON","OLD","OR","ORDER","OUTER",
            "PRIMARY","PROCEDURE","RELEASE","RESULT","RETURN","RIGHT","ROLLBACK","ROW","ROWNUM","SELECT","SET","SOME","SQL","START",
            "TABLE","THEN","TO","TOP","TREAT","TRUE","TRUNCATE","UNION","UNION","UNIQUE","UNKNOWN","UPDATE","USING","VALUE","VALUES","VIEW","WITH","WITHIN","WITHOUT","WHEN","WHERE","WHILE"
    };

std::string SYMBOLS [] = {"'", "\"", "-", ";", "=", ">", "<", "%", "?", "&"};

/* Why the uppercase function names?
 *  I thought that was C++ convention :P
 */

// quick and dirty. I don't know who was doing this. Works. 
std::string GetAuthenticationQuery(std::string username, std::string password) { 
    std::string query = "SELECT authenticate FROM passwordList WHERE name = '"
        + username + "' AND passwd = '"
        + password + "';";    
    return query;
}


std::pair<std::string, std::string> WeakMitigation(std::pair<std::string, std::string> unsanitizedInput) {
    // Deconstruct the pair of inputs
    std::string unsanitizedUsername = std::get<0>(unsanitizedInput);
    std::string unsanitizedPassword = std::get<1>(unsanitizedInput);
    
    // FIXME Sanitize the inputs
    std::string sanitizedUsername = "weak_" + unsanitizedUsername;
    std::string sanitizedPassword = "weak_" + unsanitizedPassword;

    // Put results back into a pair and send it off
    std::pair<std::string, std::string> sanitizedInput (sanitizedUsername, sanitizedPassword);
    return sanitizedInput;
}

// Helper utility. Returns toTokenize as a vector of 
// individual strings in the supplied call by reference vector
std::vector<std::string> tokenize(std::string toTokenize, std::vector<std::string>& tokens) {
    std::string tmp;
    std::stringstream sstream(toTokenize);
    while (std::getline(sstream, tmp, ' '))
    {
        tokens.push_back(tmp);
    }
    return tokens;
}


// Removes unsafe tokens from a string vector if contained in 
// whitelist (blacklist?). Uses binary_search log(n) complexity.
void sanitize(std::vector<std::string> v_unsafe, 
              std::vector<std::string> v_whitelist, 
              std::string& sanitizedUsername) {
    // using binary search on sorted v_whitelist for each token in v_unsafe
    for (int i = 0; i < v_unsafe.size(); i++) {
        if(! std::binary_search(v_whitelist.begin(), v_whitelist.end(), v_unsafe[i]))
            sanitizedUsername = i == 0 ? v_unsafe[i] : sanitizedUsername + " " + v_unsafe[i];
#ifdef TEST 
        else
            std::cout << "skipping: " + v_unsafe[i] + "\n";
#endif
    }

}

// Removes symbols. This can be modified for the backbone of weakMitigation()
// Reference: unsafe is changed!
void removeSymbols(std::string& unsafe, std::vector<std::string> symbols){
#ifdef TEST
    std::cout << "\nBefore: " + unsafe + "\n";
#endif
    for (int i = 0; i < symbols.size(); i++)
        unsafe.erase(remove(unsafe.begin(), unsafe.end(), symbols[i][0]), unsafe.end());
#ifdef TEST
    std::cout << "After: " + unsafe + "\n";
#endif
}

// Calls weakMitigation() then sanitizes the result of unsafe tokens
std::pair<std::string, std::string> StrongMitigation(std::pair<std::string, std::string> unsanitizedInput) {
    int wlSize = sizeof(WHITE_LIST)/sizeof(WHITE_LIST[0]);

    std::vector<std::string> v_unsafeName;
    std::vector<std::string> v_unsafePW;
    std::vector<std::string> v_whitelist(WHITE_LIST, WHITE_LIST+wlSize-1);
    // this should happen elsewhere, like main?
    std::sort(v_whitelist.begin(), v_whitelist.end());

#ifdef SANITY
    std::cout << "v_whitelist contains:";
    for (std::vector<std::string>::iterator it=v_whitelist.begin(); it!=v_whitelist.end(); ++it)
        std::cout << ' ' << *it;
    std::cout << '\n';
#endif

    // Deconstruct the pair of inputs
    std::string unsanitizedUsername = std::get<0>(unsanitizedInput);
    std::string unsanitizedPassword = std::get<1>(unsanitizedInput);
    std::string sanitizedUsername = "";
    std::string sanitizedPassword = "";

    // Let the mitigating begin:
    // need to first remove any symbols
    // TODO: This is where weakMitigation() would be called
    int v_symSize = sizeof(SYMBOLS)/sizeof(SYMBOLS[0]);
    std::vector<std::string> v_symbols(SYMBOLS, SYMBOLS + v_symSize-1);
    removeSymbols(unsanitizedUsername, v_symbols);
    removeSymbols(unsanitizedPassword, v_symbols);
    // for each unsanitized string, tokenize words and store in a vector
    tokenize(unsanitizedUsername, v_unsafeName);
    tokenize(unsanitizedPassword, v_unsafePW);
    // now sanitize each vector according to the whitelist
    sanitize(v_unsafeName, v_whitelist, sanitizedUsername);
    sanitize(v_unsafePW, v_whitelist, sanitizedPassword);

    // sanitizedUsername = "strong_" + unsanitizedUsername;
    // std::string sanitizedPassword = "strong_" + unsanitizedPassword;

    // Put results back into a pair and send it off
    std::pair<std::string, std::string> sanitizedInput(sanitizedUsername, sanitizedPassword);
    return sanitizedInput;
}


void RunTest(std::string unsanitizedUsername, std::string unsanitizedPassword) {
    // Display Unsanitized Inputs and Query
    std::cout << "**Unsanitized**" << std::endl;
    std::cout << "username: " << unsanitizedUsername << std::endl;
    std::cout << "password: " << unsanitizedPassword << std::endl;
    std::cout << "query:" << GetAuthenticationQuery(unsanitizedUsername,
        unsanitizedPassword) << std::endl << std::endl << std::endl;

    // Pair up the inputs to prepare for mitigation
    std::pair<std::string, std::string> unsanitizedInput(unsanitizedUsername, unsanitizedPassword);

    // Sanitize and Display New Inputs and Query
    std::cout << "**Sanitized**" << std::endl;

    // Weak Mitigation
    std::pair<std::string, std::string> weaklySanitizedInput = WeakMitigation(unsanitizedInput);
    std::string weaklySanitizedUsername = std::get<0>(weaklySanitizedInput);
    std::string weaklySanitizedPassword = std::get<1>(weaklySanitizedInput);
    std::cout << "*Weak Mitigation*" << std::endl;
    std::cout << "username: " << weaklySanitizedUsername << std::endl;
    std::cout << "password: " << weaklySanitizedPassword << std::endl;
    std::cout << "query:" << GetAuthenticationQuery(weaklySanitizedUsername,
        weaklySanitizedPassword) << std::endl << std::endl;

    // Strong Mitigation
    std::pair<std::string, std::string> stronglySanitizedInput = StrongMitigation(unsanitizedInput);
    std::string stronglySanitizedUsername = std::get<0>(stronglySanitizedInput);
    std::string stronglySanitizedPassword = std::get<1>(stronglySanitizedInput);
    std::cout << "*Strong Mitigation*" << std::endl;
    std::cout << "username: " << stronglySanitizedUsername << std::endl;
    std::cout << "password: " << stronglySanitizedPassword << std::endl;
    std::cout << "query:" << GetAuthenticationQuery(stronglySanitizedUsername,
        stronglySanitizedPassword) << std::endl << std::endl << std::endl;
}


void ValidTests() {
    std::cout << "****VALID****" << std::endl << std::endl;

    // Test #1
    std::string username = "dmoster";
    std::string password = "r3allygr8pw_";
    RunTest(username, password);

    // Test #2
    username = "mtobler";
    password = "awes0me_hat";
    RunTest(username, password);

    // Test #3
    username = "michaela";
    password = "alm0stDone";
    RunTest(username, password);

    // Test #4
    username = "mkarki";
    password = "_multi1ingu4l";
    RunTest(username, password);

    // Test #5
    username = "msalyards";
    password = "_cod3Wiz4rd_";
    RunTest(username, password);

    // Test #6
    username = "tbeeson";
    password = "w0rdSm1th_";
    RunTest(username, password);

    // Test #7
    username = "sp3ctre";
    password = "asdf456__";
    RunTest(username, password);

    // Test #8
    username = "w4lking_be4r";
    password = "a1b2c3d4_e_f_g";
    RunTest(username, password);

    // Test #9
    username = "rad_dad73";
    password = "rUbIks_CuB3";
    RunTest(username, password);

    // Test #10
    username = "TennesseeErnieFord";
    password = "_16tons";
    RunTest(username, password);

    // Test #11
    username = "gandalf_greyy";
    password = "_n3v3r_l8_";
    RunTest(username, password);

    // Test #12
    username = "_g4ndalfWhite";
    password = "Balr0gz_Bane3000";
    RunTest(username, password);
}


void TautologyAttackTests() {
    std::cout << "****TAUTOLOGY****" << std::endl << std::endl;
    //Test #1
    //Creates a statememt that is always true.
    std::string username = "nothing";
    std::string password = "password' OR 'p' = 'p";
    RunTest(username, password);

    //Test #2
    username = "admin' OR 'root' = 'root";
    password = "anything' OR 'x' = 'x";
    RunTest(username, password);
}


void UnionQueryAttackTests() {
    std::cout << "****UNION QUERY****" << std::endl << std::endl;

    // Test #1. Selects all credentials with elevated privileges
    // Assumes a column permissionLevel of NUMBER type in
    // passwordList table.
    std::string username = "some_user";
    std::string password = "password' UNION SELECT authenticate FROM passwordList WHERE permissionLevel > 0 and name like '%";
    RunTest(username, password);

    // Test #2. returns a valid authenticate token for the admin 
    // account if it exists
    username = "SYSTEM";
    password = "plainTextPassword' UNION SELECT authenticate FROM passwordList WHERE name = 'admin"; 
    RunTest(username, password);
}


void AdditionalStatementAttackTests() {
    std::cout << "****ADDITIONAL STATEMENT****" << std::endl << std::endl;

    //Test #1. Changes the password of Admin account to something simple so that the attacker can 
    //get into the system as an administrator.
    std::string username = "user";
    std::string password = "password'; update passwordList set password='12345' where user='admin";
    RunTest(username, password);
    
    //Test #2. Inserts a new user to the database.
    username = "user";
    password = "password'; INSERT INTO passwordList (name, password) VALUES 'Max', 'pass";
    RunTest(username, password);
}


void CommentAttackTests() {
    std::cout << "****COMMENT - UNDER CONSTRUCTION****" << std::endl << std::endl;
}


std::string DisplayMenu() {
    // just adding quick interface for testing.
    std::string str_num;

    std::cout << "\n\n*** MENU ***";
    std::cout << "\n1 - Valid Tests";
    std::cout << "\n2 - Tautology Attack Tests";
    std::cout << "\n3 - Union Query Attack Tests";
    std::cout << "\n4 - Additional Statement Attack Tests";
    std::cout << "\n5 - Comment Attack Tests";
    std::cout << "\n6 - Quit";

    std::cout << "\n\nEnter test #: ";
    std::cin >> str_num;
    std::cout << std::endl << std::endl;

    return str_num;
}


int main()
{
    std::string input = "";

    do {
        input = DisplayMenu();

        if (input == "1") {
            ValidTests();
        }
        else if (input == "2") {
            TautologyAttackTests();
        }
        else if (input == "3") {
            UnionQueryAttackTests();
        }
        else if (input == "4") {
            AdditionalStatementAttackTests();
        }
        else if (input == "5") {
            CommentAttackTests();
        }

    } while (input != "6");

    std::cout << "\n\nThank you for testing!\n";

    return 0;
}

