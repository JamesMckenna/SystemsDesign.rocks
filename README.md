# SystemsDesign.rocks
## Project Notes
The SystemsDesign.rocks project is an Authorization, Authentication and User Management service. The project design is to follow Service Orientated Architecture and horizontal scaling. As such, the secure token service has been implemented using Reference Tokens rather than Self-Contained, Json Web Tokens. As a result, clients and resources will be making request to the STS multiple times per single User interaction and under heavy load could cause issues – the decision was made to separate the STS from User Management and User Data Access.

Currently, the STS contacts the User Database directly and will be changed in later iterations to pull User Data from IdApi which in turn, pulls from the User Database.

IdManagement is the client application with which a User can register an account and manage their account. It will also allow one with elevated privileges to register users, assign or revoke a user’s privileges.   
   
#### IdApi: 
IdApi is a base implementation of Microsoft’s ASP.Net Core Identity and ASP.Net Core Entity Framework. At this point, only the base implementation of the UserManager class is implemented, though for any functionality that is not provided out-of-the-box, a domain layer and data access layer will be added.

In later iterations, the SignInManager class will also be implemented, and like the UserManager, if any functionality not built into ASP.Net Core Identity is required, that functionality can be added  to the BLL and DAL. 

#### IdManagement:

The DotNet Core 3.1 application, IdManagement, is a MVC client interface for user management.  Account registration and account management will be handled via this client. In future iterations, an administrator will have the ability to add a user account, disable a user account, elevate a user’s privilege to access functionality, or remove privilege to functionality.  


#### IS4:

IS4 is an implementation of the Identity Server 4, Secure Token Service. It has been built as its own application – rather than as a middleware service of a larger application – to handle multiple concurrent requests for token generation, token validation and token management.     

 

