#include <iostream>
#include <string>


std::string GetAuthenticationQuery(std::string username, std::string password) {
    std::string query = "";



    return query;
}


void ValidTests() {

}


void TautologyAttackTests() {

}


void UnionQueryAttackTests() {

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


void DisplayMenu() {

}


int main()
{
    std::string input = "";


    do {
        DisplayMenu();

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

