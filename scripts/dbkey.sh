# PicketBox Database KeyStore #
# Author: Anil Saldhana #

#Change the following (if needed)
VERSION=5.0.0-SNAPSHOT
KEYJAR=../target/picketbox-keystore-${VERSION}.jar

#Database drivers
DB_DRIVER=$HOME/.m2/repository/com/h2database/h2/1.3.168/h2-1.3.168.jar

#Bouncycastle Jar
BCPKIX=$HOME/.m2/repository/org/bouncycastle/bcpkix-jdk15on/1.47/bcpkix-jdk15on-1.47.jar
BCPROV=$HOME/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.47/bcprov-jdk15on-1.47.jar

BC=${BCPKIX}:${BCPROV}

#combined jar path
JAR=${KEYJAR}:${DB_DRIVER}:${BC}:.

java -cp ${JAR} org.picketbox.keystore.PicketBoxDBKeyStore
