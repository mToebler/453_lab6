#include <iostream>
#include <string>

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


std::string WeakMitigation(std::string input) {
    std::string sanitizedInput = "weak_";

    sanitizedInput += input;

    return sanitizedInput;
}


std::string StrongMitigation(std::string input) {
    std::string sanitizedInput = "strong_";

    sanitizedInput += input;

    return sanitizedInput;
}


void RunTest(std::string unsanitizedUsername, std::string unsanitizedPassword) {
    // Display Unsanitized Inputs and Query
    std::cout << "**Unsanitized**" << std::endl;
    std::cout << "username: " << unsanitizedUsername << std::endl;
    std::cout << "password: " << unsanitizedPassword << std::endl;
    std::cout << "query:" << GetAuthenticationQuery(unsanitizedUsername,
        unsanitizedPassword) << std::endl << std::endl << std::endl;

    // Sanitize and Display New Inputs and Query
    std::cout << "**Sanitized**" << std::endl;

    // Weak Mitigation
    std::string weaklySanitizedUsername = WeakMitigation(unsanitizedUsername);
    std::string weaklySanitizedPassword = WeakMitigation(unsanitizedPassword);
    std::cout << "*Weak Mitigation*" << std::endl;
    std::cout << "username: " << weaklySanitizedUsername << std::endl;
    std::cout << "password: " << weaklySanitizedPassword << std::endl;
    std::cout << "query:" << GetAuthenticationQuery(weaklySanitizedUsername,
        weaklySanitizedPassword) << std::endl << std::endl;

    // Strong Mitigation
    std::string stronglySanitizedUsername = StrongMitigation(unsanitizedUsername);
    std::string stronglySanitizedPassword = StrongMitigation(unsanitizedPassword);
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
    std::cout << "****TAUTOLOGY - UNDER CONSTRUCTION****" << std::endl << std::endl;
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

    //test #1. Deletes everything in the table Users.
    std::string username = "user";
    std::string password = "password'; DROP TABLE Users";
    RunTest(username, password);
    
    //test #2. Inserts a new user to the database.
    username = "user";
    password = "password'; INSERT INTO Users (name, password) VALUES 'Max', 'pass";
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

    std::cout << "\n\nThank you for testing!";

    return 0;
}

