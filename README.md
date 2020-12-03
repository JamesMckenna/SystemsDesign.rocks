# SystemsDesign.rocks
## Project Notes
The SystemsDesign.rocks project is an Authorization, Authentication and User Management service. The project design is to follow Service Orientated Architecture and horizontal scaling. As such, the secure token service has been implemented using Reference Tokens rather than Self-Contained, Json Web Tokens. As a result, clients and resources will be making request to the STS multiple times per single User interaction and under heavy load could cause issues – the decision was made to separate the STS from User Management and User Data Access.

Currently, the STS contacts the User Database directly and will be changed in later iterations to pull User Data from IdApi which in turn, pulls from the User Database.

IdManagement is the client application with which a User can register an account and manage their account. It will also allow one with elevated privileges to register users, assign or revoke a user’s privileges.   
   
#### IdApi: 
IdApi is to be the  
ASP.Net Core Identity - 

