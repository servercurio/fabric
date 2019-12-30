package com.servercurio.fabric.core.serialization;

import com.servercurio.fabric.core.serialization.spi.SerializationProvider;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.ServiceLoader;

public class ObjectSerializer {

      private ServiceLoader<SerializationProvider> serviceLoader;

      public ObjectSerializer() {
            initialize();
      }

      public <T extends SerializationAware> T deserialize(final DataInputStream inStream) throws IOException {

            if (inStream == null) {
                  throw new IllegalArgumentException("inStream");
            }

            final int namespace = inStream.readInt();
            final int id = inStream.readInt();

            final int major = inStream.readInt();
            final int minor = inStream.readInt();
            final int revision = inStream.readInt();

            final ObjectId objectId = new ObjectId(namespace, id);
            final Version version = new Version(major, minor, revision);

            final SerializationProvider provider = provider(objectId, version);

            return provider.deserialize(this, inStream, objectId, version);

      }

      public <T extends SerializationAware> void serialize(final DataOutputStream outStream, final T object) throws IOException {

            if (outStream == null) {
                  throw new IllegalArgumentException("outStream");
            }

            if (object == null) {
                  throw new IllegalArgumentException("object");
            }


            final SerializationProvider provider = provider(object);

            final Version version = object.getVersion();
            final ObjectId oid = object.getObjectId();

            outStream.writeInt(oid.getNamespace());
            outStream.writeInt(oid.getIdentifier());

            outStream.writeInt(version.getMajor());
            outStream.writeInt(version.getMinor());
            outStream.writeInt(version.getRevision());

            provider.serialize(this, outStream, object);

      }

      private void initialize() {

            if (serviceLoader == null) {
                  serviceLoader = ServiceLoader.load(SerializationProvider.class);
            }

      }

      protected <T extends SerializationAware> SerializationProvider provider(final T object) throws ObjectNotSerializableException {

            final Iterator<SerializationProvider> iter = serviceLoader.iterator();

            while (iter.hasNext()) {
                  SerializationProvider provider = iter.next();

                  if (provider.isSupported(object)) {
                        return provider;
                  }
            }

            throw new ObjectNotSerializableException(object.getClass().getName());

      }

      protected SerializationProvider provider(final ObjectId objectId, final Version version) throws UnknownObjectIdentifierException {

            final Iterator<SerializationProvider> iter = serviceLoader.iterator();

            while (iter.hasNext()) {
                  SerializationProvider provider = iter.next();

                  if (provider.isSupported(objectId, version)) {
                        return provider;
                  }
            }

            throw new UnknownObjectIdentifierException(objectId);

      }
}
