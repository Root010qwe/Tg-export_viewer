from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    Index,
)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, nullable=True)

    chats = relationship("Chat", back_populates="owner")
    chat_accesses = relationship(
        "ChatAccess",
        back_populates="user",
        foreign_keys="ChatAccess.user_id",
        cascade="all, delete-orphan"
    )


class Chat(Base):
    __tablename__ = "chats"

    id = Column(Integer, primary_key=True, index=True)
    # Название чата
    title = Column(String, nullable=False)
    # Имя папки экспорта (для base href и доступа к css/js/media)
    export_folder = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=True)

    # Владелец чата
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)

    # Хэш пароля (если установлен)
    password_hash = Column(String, nullable=True)

    owner = relationship("User", back_populates="chats")
    messages = relationship("Message", back_populates="chat")
    accesses = relationship("ChatAccess", back_populates="chat", cascade="all, delete-orphan")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), index=True)

    telegram_message_id = Column(Integer, nullable=True, index=True)

    sender = Column(String, nullable=True)
    sender_id = Column(String, nullable=True)

    date = Column(DateTime, nullable=True, index=True)

    # индекс порядка сообщений в чате (как в оригинальном HTML)
    order_index = Column(Integer, nullable=False, index=True)

    # Очищенный текст (для поиска)
    text = Column(Text, nullable=True)

    # Сырой HTML для рендера
    raw_html = Column(Text, nullable=True)

    has_media = Column(Boolean, default=False)
    media_type = Column(String, nullable=True)
    media_path = Column(String, nullable=True)

    chat = relationship("Chat", back_populates="messages")


class ChatAccess(Base):
    __tablename__ = "chat_accesses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False, index=True)
    granted_at = Column(DateTime, nullable=True)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # Кто выдал доступ

    user = relationship("User", back_populates="chat_accesses", foreign_keys=[user_id])
    chat = relationship("Chat", back_populates="accesses")
    granter = relationship("User", foreign_keys=[granted_by], post_update=True)

    # Уникальный индекс: один пользователь не может иметь два доступа к одному чату
    __table_args__ = (
        Index("idx_chat_access_unique", user_id, chat_id, unique=True),
    )


Index("idx_messages_chat_date", Message.chat_id, Message.date)
Index("idx_messages_chat_text", Message.chat_id, Message.text)
Index("idx_messages_chat_order", Message.chat_id, Message.order_index)
