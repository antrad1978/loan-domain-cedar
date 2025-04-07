@id("manage-users")
permit (
    principal is LoanPlatform::User,
    action in [LoanPlatform::Action::"CreateUser", 
    LoanPlatform::Action::"EditUser",
    LoanPlatform::Action::"DeleteUser"],
    resource is LoanPlatform::User 
)
when {
    (context.sourceIp.isInRange(ip("10.0.0.0/8")) ||
    context.sourceIp.isInRange(ip("172.16.0.0/12"))) &&
    principal.roles.contains("administrator")  
};

@id("edit-customer")
permit (
    principal is LoanPlatform::User,
    action in [LoanPlatform::Action::"EditCustomer"],
    resource is LoanPlatform::Customer 
)
when {
    (context.sourceIp.isInRange(ip("10.0.0.0/8")) ||
    context.sourceIp.isInRange(ip("172.16.0.0/12"))) &&
    principal.roles.contains("officer")  
};
