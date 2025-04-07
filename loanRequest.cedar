@id("submit-loan-request")
permit (
    principal is LoanPlatform::Customer,
    action == LoanPlatform::Action::"SubmitLoanRequest",
    resource is LoanPlatform::LoanRequest
    )
when {
    principal.KYC == true && 
    principal.emailValidate == true &&
    principal.phoneNumberValidate == true &&
    principal.enabled == true
};

@id("submit-loan-request-document-submit")
permit (
    principal is LoanPlatform::Customer,
    action == LoanPlatform::Action::"SubmitLoanRequest",
    resource is LoanPlatform::LoanRequest
)
when {
    principal.KYC == true && 
    principal.emailValidate == true &&
    principal.phoneNumberValidate == true &&
    principal.enabled == true &&
    resource.owner == principal.username
};

@id("loan-request-ai-validate")
permit (
    principal is LoanPlatform::AIAgent,
    action == LoanPlatform::Action::"ValidationAIBased",
    resource is LoanPlatform::LoanRequest
)
when{
    principal.identity == "ai-job"
};

@id("loan-request-change-status")
permit (
    principal is LoanPlatform::User,
    action == LoanPlatform::Action::"ChangeLoanRequestStatus",
    resource is LoanPlatform::LoanRequest
) 
when {
    principal.enabled == true &&
    resource.officer == principal.username &&
    (context.sourceIp.isInRange(ip("10.0.0.0/8")) ||
    context.sourceIp.isInRange(ip("172.16.0.0/12"))) &&
    (context.currentTime >= 9 && 
        context.currentTime < 17) &&
        principal.roles.contains("loan-officer") 
};