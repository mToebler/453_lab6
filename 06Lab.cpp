#include <iostream>
#include <string>

/* Why the uppercase function names? */

// quick and dirty. I don't know who was doing this. Works. 
std::string GetAuthenticationQuery(std::string username, std::string password) { 
    std::string query = "SELECT authenticate FROM passwordList WHERE name = '"
        + username + "' AND passwd = '"
        + password + "';";    
    return query;
}


void ValidTests() {

}


void TautologyAttackTests() {

}


void UnionQueryAttackTests() {
    // Test #1. Selects all credentials with elevated privleges
    // Assumes a column permissionLevel of NUMBER type in
    // passwordList table.
    std::string username = "some_user";
    std::string password = "password' UNION SELECT authenticate FROM passwordList WHERE permissionLevel > 0 and name like '%";
    std::string query = GetAuthenticationQuery(username, password);
    // print query?
    std::cout << "\nTEST 1: " + query;

    // Test #2. returns a valid authenticate token for the admin 
    // account if it exists
    username = "SYSTEM";
    password = "plainTextPassword' UNION SELECT authenticate FROM passwordList WHERE name = 'admin"; 
    query = GetAuthenticationQuery(username, password);
    std::cout << "\n\nTEST 2: " + query;

}


void AdditionalStatementAttackTests() {

    //test #1. Deletes everything in the table Users.
    std::string username = "user";
    std::string password = "password'; DROP TABLE Users";
    GetAuthenticationQuery(username, password);
    
    //test #2. Inserts a new user to the database.
    username = "user";
    password = "password'; INSERT INTO Users (name, password) VALUES 'Max', 'pass";
    GetAuthenticationQuery(username, password);
}


void CommentAttackTests() {

}


std::string WeakMitigation(std::string input) {
    std::string sanitizedInput;


    return sanitizedInput;
}


std::string StrongMitigation(std::string input) {
    std::string sanitizedInput;


    return sanitizedInput;
}


std::string DisplayMenu() {
    // just adding quick interface for testing.
    std::string str_num;
    std::cout << "\n\nEnter test #: ";
    std::cin >> str_num;
    return str_num;
}


int main()
{
    std::string input = "";

    do {
        input = DisplayMenu();

        std:: cout << "Enter a number: ";
        std::cin >> input;

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
        else if (input == "6") {
            WeakMitigation(input); //Change
        }
        else if (input == "7") {
            StrongMitigation(input);
        }

    } while (input != "8");

    return 0;
}
