package vault

func (v *Vault) RenewLease() error {
	return v.client.Client.TokenRenewSelf()
}
