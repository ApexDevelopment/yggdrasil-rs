package multicast

// Exports internals for yggdrasil-rs's interop tests.

func ExportEncodeAdvertisement(major, minor uint16, key []byte, port uint16, hash []byte) []byte {
	adv := multicastAdvertisement{major, minor, key, port, hash}
	b, _ := adv.MarshalBinary()
	return b
}

func ExportDecodeAdvertisement(b []byte) (major, minor uint16, key []byte, port uint16, hash []byte, err error) {
	var adv multicastAdvertisement
	err = adv.UnmarshalBinary(b)
	return adv.MajorVersion, adv.MinorVersion, adv.PublicKey, adv.Port, adv.Hash, err
}
