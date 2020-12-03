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


#### TODO:
* Tweak Logging. Logging for all services will need to be expanded upon and improved. It is anticipated that this will be ongoing throughout the SDLC iterations. In a future iteration, move logs from flat file to a database (NOSQL?).

* Ongoing monitoring of http headers and content sercuirty policies.  

* Add Authorization Policies, the out-of-the-box User Roles and User Claims required by an organization to build upon.  Roles such as Administrator, Manager, Member and Developer with claims for read, write, update and delete privileges.  IdManagement will need pages to add new roles and claims that are organization specific . These roles and claims will be persisted to the User Database through the IdApi.

*  Move email sending and SMS messaging responsibility from IdManagement to IdApi. Remove ASP.Net Core Identity dependency from IdManagement. The intent is to have a loosely coupled client, a client that makes a request to a 'black-box' that handles all user data.  

* Remove SignInManager from IS4. IS4 should make requests to IdApi for all user related data. Currently, IS4 makes requests directly to the User Database.

* Remove AddDistributedMemoryCache() and implement a better caching strategy.

* Remove the InMemory implementation for Identity Server 4 configuration and operational data. Implementing persistent storage for both configuration data and operations data will allow for client applications and service APIs to be added without needing to rebuild and re-deploy the STS application. This will give more freedom to an organization, allow for a better CI/CD pipeline in a multi-service application. Will allow developers to build new applications / services with full login and authorization support from thier development environment.      

* Add a UI and functionality to IS4 so one with the Developer Role can add client applications and service APIs to the STS as they become ready for deployment.

* Make the public facing applications / web pages look pretty. A homogenous layout and design theme across the IdManagement, IS4 Login / Logout, and Main Client applications. Come to a decision on a Main Client framework. Leaning towards VueJs with a DotNet Core backend. The Main Client app is the main public facing website with blogging functionality. With it, an API will be needed for the blogging CRUD operations. If Backend For Frontend Architecture is used, this can all be built as a single Dot Net Core application. Automated testing will be needed.

* Currently, the AppilcationUser class is inherited from ASP.Net IdentityUser. Eventually, the ApplicationUser class will need more properties and behaviour. Things to keep in mind: ApplicationUser could be an individual or an organization, and as such, ApplicationUser may itself become a base class for the larger applcation / services.

* Containerize all services



