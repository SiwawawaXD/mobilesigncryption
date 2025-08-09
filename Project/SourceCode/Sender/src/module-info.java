module MobileSignCryption6 {
	requires org.bouncycastle.provider;
	requires org.json;
	requires okio;           // OkHttp depends on Okio
    requires okhttp3;         // export the relevant packages (adjust based on OkHttp's internal structure)
}