#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <assert.h>

static std::string SQL_ARRAY [] = {
            "ABS","ADD","ALTER","ALL","AND","ANY","AS","ASC","BACKUP","BEFORE","BEGIN","BETWEEN","BY","CALL","CASE","CAST","CHECK","COLLATE","COLUMN","COUNT","COMMIT","CONSTRAINT","CREATE","CROSS","CURRENT","CURSOR",
            "DATABASE","DEALLOCATE","DECLARE","DESCRIBE","DEFAULT","DELETE","DESC","DISTINCT","DROP","ELSE","END","ESCAPE","EXEC","EXECUTE","EXISTS","FALSE","FETCH","FOREIGN","FROM","FULL","FUNCTION",
            "GET","GLOBAL","GRANT","GROUP","HAVING","HOLD","IN","INDEX","INNER","INSERT","INTO","IS","JOIN",
            "LEFT","LIKE","LIMIT","MATCH","MODIFIES","NEW","NEXT","NO","NOT","NULL","OR","ON","OLD","OR","ORDER","OUTER",
            "PRIMARY","PROCEDURE","RELEASE","RESULT","RETURN","RIGHT","ROLLBACK","ROW","ROWNUM","SELECT","SET","SOME","SQL","START",
            "TABLE","THEN","TO","TOP","TREAT","TRUE","TRUNCATE","UNION","UNION","UNIQUE","UNKNOWN","UPDATE","USING","VALUE","VALUES","VIEW","WHEN","WHERE","WHILE","WITH","WITHIN","WITHOUT"
    };

// quick and dirty. I don't know who was doing this. Works. 
std::string getAuthenticationQuery(std::string username, std::string password) { 
    std::string query = "SELECT authenticate FROM passwordList WHERE name = '"
        + username + "' AND passwd = '"
        + password + "';";    
    return query;
}


// Helper utility. Returns param:toTokenize as a vector of 
// individual strings in the supplied vector (call by referenced)
std::vector<std::string> tokenize(std::string toTokenize, std::vector<std::string>& tokens) {
    std::string tempStr;
    std::stringstream sstream(toTokenize);
    while (std::getline(sstream, tempStr, ' '))
    {
        tokens.push_back(tempStr);
    }
    return tokens;
}


// Removes unsafe tokens from a string vector if contained in 
// sql command list. Uses binary_search log(n) complexity.
void sanitize(std::vector<std::string> v_unsafe, 
              std::vector<std::string> v_sqlList, 
              std::string& sanitizedUsername) {
    // using binary search on sorted v_sqlList for each token in v_unsafe
    for (int i = 0; i < v_unsafe.size(); i++) {
        if(! std::binary_search(v_sqlList.begin(), v_sqlList.end(), v_unsafe[i]))
            sanitizedUsername = i == 0 ? v_unsafe[i] : sanitizedUsername + " " + v_unsafe[i];
    }
}

// removes any character not in the approved 
// set AZaz09_ SPACE CRLF
std::string removeInvalidChars(std::string unsafe) {
    // Use the string's iterators to
    // copy only chars within set{LF, CR, SPACE, 0-9, A-Z, _, a-z}
    // ASCII values of set: (10, 13, 32, 48-57, 65-90, 95, 97-122)
    std::string safeStr = "";
    // std::for_each(unsafe.begin(), unsafe.end(), copySafeChar);
    for (std::string::const_iterator it = unsafe.cbegin(); it != unsafe.cend(); ++it) {
        switch ((int)*it) {
            case 10:         // LF
            case 13:         // CR
            case 32:         // SPACE
            case 48 ... 57:  // 0 - 9
            case 65 ... 90:  // A-Z
            case 95:         // _
            case 97 ... 122: // a-z
                safeStr += (char)*it;
                break;

            default:
                break;
        };
    }
    return safeStr;
}

std::string removeSpaces(std::string unsafe) {
    // using the string's iterators to
    // copy only chars within set{LF, CR, 0-9, A-Z, _, a-z}
    // ASCII values of set: (10, 13, 48-57, 65-90, 95, 97-122)
    std::string safeStr = "";
    // std::for_each(unsafe.begin(), unsafe.end(), copySafeChar);
    for (std::string::const_iterator it = unsafe.cbegin(); it != unsafe.cend(); ++it) {
        switch ((int)*it) {
            case 10:         // LF
            case 13:         // CR
            //case 32:         // SPACE
            case 48 ... 57:  // 0 - 9
            case 65 ... 90:  // A-Z
            case 95:         // _
            case 97 ... 122: // a-z
                safeStr += (char)*it;
                break;

            default:
                break;
        };
    }
    return safeStr;
}


std::pair<std::string, std::string> weakMitigation(std::pair<std::string, std::string> unsanitizedInput) {
    // Deconstruct the pair of inputs
    std::string unsanitizedUsername = std::get<0>(unsanitizedInput);
    std::string unsanitizedPassword = std::get<1>(unsanitizedInput);

    std::string sanitizedUsername = removeInvalidChars(unsanitizedUsername);
    std::string sanitizedPassword = removeInvalidChars(unsanitizedPassword);
    // Put results back into a pair and send it off
    std::pair<std::string, std::string>
        sanitizedInput(sanitizedUsername, sanitizedPassword);
    return sanitizedInput;
}

// Calls weakMitigation() then sanitizes the result of unsafe tokens
std::pair<std::string, std::string> strongMitigation(std::pair<std::string, std::string> unsanitizedInput) {
    int wlSize = sizeof(SQL_ARRAY)/sizeof(SQL_ARRAY[0]);

    std::vector<std::string> v_unsafeName;
    std::vector<std::string> v_unsafePW;
    std::vector<std::string> v_sqllist(SQL_ARRAY, SQL_ARRAY+wlSize-1);
    
    // call Weak Mitigation
    unsanitizedInput = weakMitigation(unsanitizedInput);
    // Deconstruct the pair of inputs
    std::string unsanitizedUsername = std::get<0>(unsanitizedInput);
    std::string unsanitizedPassword = std::get<1>(unsanitizedInput);
    std::string sanitizedUsername = "";
    std::string sanitizedPassword = "";

    // With symbols removed by weakMitigation, let the strong mitigating begin:
    // convert the strings into token vectors
    tokenize(unsanitizedUsername, v_unsafeName);
    tokenize(unsanitizedPassword, v_unsafePW);
    // now sanitize each vector according to the sql command list
    sanitize(v_unsafeName, v_sqllist, sanitizedUsername);
    sanitize(v_unsafePW, v_sqllist, sanitizedPassword);
    // remove spaces in a final pass
    sanitizedUsername = removeSpaces(sanitizedUsername);
    sanitizedPassword = removeSpaces(sanitizedPassword);

    // Put results back into a pair and send it off
    std::pair<std::string, std::string> sanitizedInput(sanitizedUsername, sanitizedPassword);
    return sanitizedInput;
}


void runTest(std::string unsanitizedUsername, std::string unsanitizedPassword) {
    // Display Unsanitized Inputs and Query
    std::cout << "**Unsanitized**" << std::endl;
    std::cout << "username: " << unsanitizedUsername << std::endl;
    std::cout << "password: " << unsanitizedPassword << std::endl;
    std::cout << "query:" << getAuthenticationQuery(unsanitizedUsername,
        unsanitizedPassword) << std::endl << std::endl << std::endl;

    // Pair up the inputs to prepare for mitigation
    std::pair<std::string, std::string> unsanitizedInput(unsanitizedUsername, unsanitizedPassword);

    // Sanitize and Display New Inputs and Query
    std::cout << "**Sanitized**" << std::endl;

    // Weak Mitigation
    std::pair<std::string, std::string> weaklySanitizedInput = weakMitigation(unsanitizedInput);
    std::string weaklySanitizedUsername = std::get<0>(weaklySanitizedInput);
    std::string weaklySanitizedPassword = std::get<1>(weaklySanitizedInput);
    std::cout << "*Weak Mitigation*" << std::endl;
    std::cout << "username: " << weaklySanitizedUsername << std::endl;
    std::cout << "password: " << weaklySanitizedPassword << std::endl;
    std::cout << "query:" << getAuthenticationQuery(weaklySanitizedUsername,
        weaklySanitizedPassword) << std::endl << std::endl;

    // Strong Mitigation
    std::pair<std::string, std::string> stronglySanitizedInput = strongMitigation(unsanitizedInput);
    std::string stronglySanitizedUsername = std::get<0>(stronglySanitizedInput);
    std::string stronglySanitizedPassword = std::get<1>(stronglySanitizedInput);
    std::cout << "*Strong Mitigation*" << std::endl;
    std::cout << "username: " << stronglySanitizedUsername << std::endl;
    std::cout << "password: " << stronglySanitizedPassword << std::endl;
    std::cout << "query:" << getAuthenticationQuery(stronglySanitizedUsername,
        stronglySanitizedPassword) << std::endl << std::endl << std::endl;
}


void validTests() {
    std::cout << "****VALID****" << std::endl << std::endl;

    // Test #1
    std::string username = "dmoster";
    std::string password = "r3allygr8pw_";
    runTest(username, password);

    // Test #2
    username = "mtobler";
    password = "awes0me_hat";
    runTest(username, password);

    // Test #3
    username = "michaela";
    password = "alm0stDone";
    runTest(username, password);

    // Test #4
    username = "mkarki";
    password = "_multi1ingu4l";
    runTest(username, password);

    // Test #5
    username = "msalyards";
    password = "_cod3Wiz4rd_";
    runTest(username, password);

    // Test #6
    username = "tbeeson";
    password = "w0rdSm1th_";
    runTest(username, password);

    // Test #7
    username = "sp3ctre";
    password = "asdf456__";
    runTest(username, password);

    // Test #8
    username = "w4lking_be4r";
    password = "a1b2c3d4_e_f_g";
    runTest(username, password);

    // Test #9
    username = "rad_dad73";
    password = "rUbIks_CuB3";
    runTest(username, password);

    // Test #10
    username = "TennesseeErnieFord";
    password = "_16tons";
    runTest(username, password);

    // Test #11
    username = "gandalf_greyy";
    password = "_n3v3r_l8_";
    runTest(username, password);

    // Test #12
    username = "_g4ndalfWhite";
    password = "Balr0gz_Bane3000";
    runTest(username, password);
}


void tautologyAttackTests() {
    std::cout << "****TAUTOLOGY****" << std::endl << std::endl;
    //Test #1
    //Creates a statememt that is always true.
    std::string username = "nothing";
    std::string password = "password' OR 'p' = 'p";
    runTest(username, password);

    //Test #2
    username = "admin' OR 'root' = 'root";
    password = "anything' OR 'x' = 'x";
    runTest(username, password);
}


void unionQueryAttackTests() {
    std::cout << "****UNION QUERY****" << std::endl << std::endl;

    // Test #1. Selects all credentials with elevated privileges
    // Assumes a column permissionLevel of NUMBER type in
    // passwordList table.
    std::string username = "some_user";
    std::string password = "password' UNION SELECT authenticate FROM passwordList WHERE permissionLevel > 0 and name like '%";
    runTest(username, password);

    // Test #2. returns a valid authenticate token for the admin 
    // account if it exists
    username = "SYSTEM";
    password = "plainTextPassword' UNION SELECT authenticate FROM passwordList WHERE name = 'admin"; 
    runTest(username, password);
}


void additionalStatementAttackTests() {
    std::cout << "****ADDITIONAL STATEMENT****" << std::endl << std::endl;

    //Test #1. Changes the password of Admin account to something simple so that the attacker can 
    //get into the system as an administrator.
    std::string username = "user";
    std::string password = "password'; update passwordList set password='12345' where user='admin";
    runTest(username, password);
    
    //Test #2. Inserts a new user to the database.
    username = "user";
    password = "password'; INSERT INTO passwordList (name, password) VALUES 'Max', 'pass";
    runTest(username, password);
}



void commentAttackTests() {
    std::cout << "****COMMENT ATTACK****" << std::endl << std::endl;

    //Test #1. Inserts a comment to the end of the user so the program ignores the password prompt.
    std::string username = "user'; -- ";
    std::string password = "password";

    runTest(username, password);
}


std::string displayMenu() {
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
    // Let's make sure 
    assert(std::is_sorted(SQL_ARRAY->begin(), SQL_ARRAY->end()));
    std::string input = "";

    do {
        input = displayMenu();

        if (input == "1") {
            validTests();
        }
        else if (input == "2") {
            tautologyAttackTests();
        }
        else if (input == "3") {
            unionQueryAttackTests();
        }
        else if (input == "4") {
            additionalStatementAttackTests();
        }
        else if (input == "5") {
            commentAttackTests();
        }

    } while (input != "6");

    std::cout << "\n\nThank you for testing!\n";

    return 0;
}

