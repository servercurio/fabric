import com.servercurio.fabric.core.security.spi.SecuritySerializationProvider;
import com.servercurio.fabric.core.serialization.spi.SerializationProvider;

module sc.fabric.core {


    requires org.apache.commons.lang3;

    uses SerializationProvider;
    provides SerializationProvider with SecuritySerializationProvider;

}