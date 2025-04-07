@id("customer-enabled")
permit (
    principal is LoanPlatform::Customer,
    action == LoanPlatform::Action::"Enable",
    resource is LoanPlatform::Customer 
)
when {
    principal.enabled == true && 
    principal.emailValidate == true &&
    principal.phoneNumberValidate == true &&
    resource.username == principal.username 
};

@id("kyc-ready")
permit (
    principal is LoanPlatform::Customer,
    action == LoanPlatform::Action::"KYCready",
    resource is LoanPlatform::Customer
)
when {
    principal.emailValidate == true &&
    principal.phoneNumberValidate == true
};

@id("customer-loyalty")
permit (
    principal is LoanPlatform::User,
    action == LoanPlatform::Action::"SetLoyalty",
    resource is LoanPlatform::Customer 
)
when {
    principal.enabled == true && 
    resource.username == principal.username 
};

    