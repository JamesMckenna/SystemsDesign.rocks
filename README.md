# SystemsDesign.rocks
## Project Notes
The SystemsDesign.rocks project is an Authorization, Authentication and User Management service. The project design is to follow Service Orientated Architecture and horizontal scaling. As such, the secure token service has been implemented using Reference Tokens rather than Self-Contained, Json Web Tokens. As a result, clients and resources will be making request to the STS many times and under heavy load could cause issues – the decision was made to separate the STS from User Management and User Data Access.   
#### IdApi: 
IdApi is to be the  
ASP.Net Core Identity - 

