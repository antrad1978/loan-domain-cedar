@id("make-monthly-payment")
permit (
    principal is LoanPlatform::Customer,
    action == LoanPlatform::Action::"Pay",
    resource is LoanPlatform::Loan
    )
when {
    resource.customer == principal.username
};
