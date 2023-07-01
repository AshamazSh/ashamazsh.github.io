/**
 * @constant {Number} CADESCOM_STRING_TO_UCS2LE Данные будут перекодированы в UCS - 2 little endian.
 */
const CADESCOM_STRING_TO_UCS2LE = 0x00;
/**
 * @constant {Number} CADESCOM_BASE64_TO_BINARY Данные будут перекодированы из Base64 в бинарный массив.
 */
const CADESCOM_BASE64_TO_BINARY = 0x01;
/**
 * @constant {Number} CADESCOM_LOCAL_MACHINE_STORE Локальное хранилище компьютера.
 */
const CADESCOM_LOCAL_MACHINE_STORE = 1;
/**
 * @constant {Number} CADESCOM_CURRENT_USER_STORE Хранилище текущего пользователя.
 */
const CADESCOM_CURRENT_USER_STORE = 2;
/**
 * @constant {Number} CADESCOM_CONTAINER_STORE
 * Хранилище сертификатов в контейнерах закрытых ключей.
 * В данный Store попадут все сертификаты из контейнеров закрытых ключей которые
 * доступны в системе в момент открытия.
 */
const CADESCOM_CONTAINER_STORE = 100;
/**
 * @constant {Number} CADESCOM_CADES_DEFAULT Тип подписи по умолчанию(CAdES - X Long Type 1).
 */
const CADESCOM_CADES_DEFAULT = 0;
/**
 * @constant {Number} CADESCOM_CADES_BES Тип подписи CAdES BES.
 */
const CADESCOM_CADES_BES = 1;
/**
 * @constant {Number} CADESCOM_CADES_T Тип подписи CAdES - T.
 */
const CADESCOM_CADES_T = 0x5;
/**
 * @constant {Number} CADESCOM_CADES_X_LONG_TYPE_1 Тип подписи CAdES - X Long Type 1.
 */
const CADESCOM_CADES_X_LONG_TYPE_1 = 0x5d;
/**
 * @constant {Number} CADESCOM_ENCODE_BASE64 Кодировка BASE64.
 */
const CADESCOM_ENCODE_BASE64 = 0;
/**
 * @constant {Number} CADESCOM_ENCODE_BINARY Бинарные данные.
 */
const CADESCOM_ENCODE_BINARY = 1;
/**
 * @constant {Number} CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME Название документа.
 */
const CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME = 1;
/**
 * @constant {Number} CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION Описание документа.
 */
const CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION = 2;
/**
 * @constant {Number} CADESCOM_ATTRIBUTE_OTHER Прочие атрибуты.
 */
const CADESCOM_ATTRIBUTE_OTHER = -1;
/**
 * @constant {Number} CADESCOM_DISPLAY_DATA_NONE Данные не будут пересылаться в устройство.
 */
const CADESCOM_DISPLAY_DATA_NONE = 0;
/**
 * @constant {Number} CADESCOM_DISPLAY_DATA_CONTENT Отображаемые данные лежат в теле сообщения.
 */
const CADESCOM_DISPLAY_DATA_CONTENT = 1;
/**
 * @constant {Number} CADESCOM_DISPLAY_DATA_ATTRIBUTE Отображаемые данные лежат в подписанном атрибуте сообщения.
 */
const CADESCOM_DISPLAY_DATA_ATTRIBUTE = 2;
/**
 * @constant {Object} Алгоритм RSA
 */
const CADESCOM_ENCRYPTION_ALGORITHM_RC = {
    /**
     * @constant {Number} RC2 Алгоритм RSA RC2.
     */
    RC2: 0,
    /**
     * @constant {Number} RC4 Алгоритм RSA RC4.
     */
    RC4: 1,
};
/**
 * @constant {Number} CADESCOM_ENCRYPTION_ALGORITHM_DES Алгоритм DES.
 */
const CADESCOM_ENCRYPTION_ALGORITHM_DES = 2;
/**
 * @constant {Number} CADESCOM_ENCRYPTION_ALGORITHM_3DES Алгоритм 3 DES.
 */
const CADESCOM_ENCRYPTION_ALGORITHM_3DES = 3;
/**
 * @constant {Number} CADESCOM_ENCRYPTION_ALGORITHM_AES Алгоритм AES.
 */
const CADESCOM_ENCRYPTION_ALGORITHM_AES = 4;
/**
 * @constant {Number} CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89 Алгоритм ГОСТ 28147 - 89.
 */
const CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89 = 25;
/**
 * @constant {Number} CADESCOM_HASH_ALGORITHM_SHA1 Алгоритм SHA1.
 */
const CADESCOM_HASH_ALGORITHM_SHA1 = 0;
/**
 * @constant {Number} CADESCOM_HASH_ALGORITHM Алгоритм MD.
 */
const CADESCOM_HASH_ALGORITHM = {
    /**
     * @constant {Number} CADESCOM_HASH_ALGORITHM_MD2 Алгоритм MD2.
     */
    MD2: 1,
    /**
     * @constant {Number} CADESCOM_HASH_ALGORITHM_MD4 Алгоритм MD4.
     */
    MD4: 2,
    /**
     * @constant {Number} CADESCOM_HASH_ALGORITHM_MD5 Алгоритм MD5.
     */
    MD5: 3,
};
/**
 * @constant {Number} CADESCOM_HASH_ALGORITHM_SHA_256 Алгоритм SHA1 с длиной ключа 256 бит.
 */
const CADESCOM_HASH_ALGORITHM_SHA_256 = 4;
/**
 * @constant {Number} CADESCOM_HASH_ALGORITHM_SHA_384 Алгоритм SHA1 с длиной ключа 384 бита.
 */
const CADESCOM_HASH_ALGORITHM_SHA_384 = 5;
/**
 * @constant {Number} CADESCOM_HASH_ALGORITHM_SHA_512 Алгоритм SHA1 с длиной ключа 512 бит.
 */
const CADESCOM_HASH_ALGORITHM_SHA_512 = 6;
/**
 * @constant {Number} CADESCOM_HASH_ALGORITHM_CP_GOST_3411 Алгоритм ГОСТ Р 34.11 - 94.
 */
const CADESCOM_HASH_ALGORITHM_CP_GOST_3411 = 100;
/**
 * @constant {Number} CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256 Алгоритм ГОСТ Р 34.10 - 2012.
 */
const CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256 = 101;
/**
 * @constant {Number} CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512 Алгоритм ГОСТ Р 34.10 - 2012.
 */
const CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512 = 102;
/**
 * @constant {Number} CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED Вложенная подпись.
 */
const CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED = 0;
/**
 * @constant {Number} CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING Оборачивающая подпись.
 */
const CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING = 1;
/**
 * @constant {Number} CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE Подпись по шаблону.
 */
const CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE = 2;
/**
 * @constant {Number} CAPICOM_LOCAL_MACHINE_STORE Локальное хранилище компьютера.
 */
const CAPICOM_LOCAL_MACHINE_STORE = 1;
/**
 * @constant {Number} CAPICOM_CURRENT_USER_STORE Хранилище текущего пользователя.
 */
const CAPICOM_CURRENT_USER_STORE = 2;
/**
 * @constant {String} CAPICOM_MY_STORE Хранилище персональных сертификатов пользователя.
 */
const CAPICOM_MY_STORE = 'My';
/**
 * @constant {Number} CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED
 * Открывает хранилище на чтение/запись, если пользователь имеет права на чтение/запись.
 * Если прав на запись нет, то хранилище открывается за чтение.
 */
const CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT
 * Сохраняет все сертификаты цепочки за исключением корневого.
 */
const CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT = 0;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY Сертификат включает только конечное лицо
 */
const CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY = 2;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN Сохраняет полную цепочку.
 */
const CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN = 1;
/**
 * @constant {Number} CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME Возвращает имя наименования сертификата.
 */
const CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME = 0;
/**
 * @constant {Number} CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME Возвращает имя издателя сертификата.
 */
const CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME = 1;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_SHA1_HASH Возвращает сертификаты соответствующие указанному хэшу SHA1.
 */
const CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME
 * Возвращает сертификаты, наименование которого точно или частично совпадает с указанным.
 */
const CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME = 1;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_ISSUER_NAME
 * Возвращает сертификаты, наименование издателя которого точно или частично совпадает с указанным.
 */
const CAPICOM_CERTIFICATE_FIND_ISSUER_NAME = 2;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_ROOT_NAME
 * Возвращает сертификаты, у которых наименование корневого точно или частично совпадает с указанным.
 */
const CAPICOM_CERTIFICATE_FIND_ROOT_NAME = 3;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_TEMPLATE_NAME
 * Возвращает сертификаты, у которых шаблонное имя точно или частично совпадает с указанным.
 */
const CAPICOM_CERTIFICATE_FIND_TEMPLATE_NAME = 4;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_EXTENSION
 * Возвращает сертификаты, у которых имеется раширение, совпадающее с указанным.
 */
const CAPICOM_CERTIFICATE_FIND_EXTENSION = 5;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY
 * Возвращает сертификаты, у которых идентификатор раширенного свойства совпадает с указанным.
 */
const CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY = 6;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_CERTIFICATE_POLICY
 * Возвращает сертификаты, содержащие указанный OID политики.
 */
const CAPICOM_CERTIFICATE_FIND_CERTIFICATE_POLICY = 8;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_TIME_VALID Возвращает действующие на текущее время сертификаты.
 */
const CAPICOM_CERTIFICATE_FIND_TIME_VALID = 9;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_TIME_NOT_YET_VALID Возвращает сертификаты, время которых невалидно.
 */
const CAPICOM_CERTIFICATE_FIND_TIME_NOT_YET_VALID = 10;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_TIME_EXPIRED Возвращает просроченные сертификаты.
 */
const CAPICOM_CERTIFICATE_FIND_TIME_EXPIRED = 11;
/**
 * @constant {Number} CAPICOM_CERTIFICATE_FIND_KEY_USAGE
 * Возвращает сертификаты, содержащие ключи, которые могут быть использованны указанным способом.
 */
const CAPICOM_CERTIFICATE_FIND_KEY_USAGE = 12;
/**
 * @constant {Number} CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE Ключ может быть использован для создания цифровой подписи.
 */
const CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE = 128;
/**
 * @constant {Number} CAPICOM_PROPID_ENHKEY_USAGE EKU.
 */
const CAPICOM_PROPID_ENHKEY_USAGE = 9;
/**
 * @constant {Number} CAPICOM_PROPID_KEY_PROV_INFO информация о ключе
 */
const CAPICOM_PROPID_KEY_PROV_INFO = 2;
/**
 * @constant {Number} CAPICOM_OID_OTHER Объект не соответствует ни одному из предуставленных типов.
 */
const CAPICOM_OID_OTHER = 0;
/**
 * @constant {Number} CAPICOM_OID_KEY_USAGE_EXTENSION
 * Расширение сертификата, содержащее информацию о назначении открытого ключа.
 */
const CAPICOM_OID_KEY_USAGE_EXTENSION = 10;
/**
 * @constant {Number} CAPICOM_EKU_OTHER Сертификат может быть использован для чего-то, что не предустановлено.
 */
const CAPICOM_EKU_OTHER = 0;
/**
 * @constant {Number} CAPICOM_EKU_SERVER_AUTH Сертификат может быть использован для аутентификации сервера.
 */
const CAPICOM_EKU_SERVER_AUTH = 1;
/**
 * @constant {Number} CAPICOM_EKU_CLIENT_AUTH Сертификат может быть использован для аутентификации клиента.
 */
const CAPICOM_EKU_CLIENT_AUTH = 2;
/**
 * @constant {Number} CAPICOM_EKU_CODE_SIGNING Сертификат может быть использован для создания цифровой подписи.
 */
const CAPICOM_EKU_CODE_SIGNING = 3;
/**
 * @constant {Number} CAPICOM_EKU_EMAIL_PROTECTION Сертификат может быть использован для защиты электронной подписи.
 */
const CAPICOM_EKU_EMAIL_PROTECTION = 4;
/**
 * @constant {Number} CAPICOM_EKU_SMARTCARD_LOGON Сертификат может быть использован для входа со смарт карты.
 */
const CAPICOM_EKU_SMARTCARD_LOGON = 5;
/**
 * @constant {Number} CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME Время подписи.
 */
const CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0;
/**
 * @constant {String} XmlDsigGost3410Url Алгоритм подписи для XmlDsig.
 */
const XmlDsigGost3410Url = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411';

/**
 * @constant {String} XmlDsigGost3411Url Алгоритм подписи для XmlDsig.
 */
const XmlDsigGost3411Url = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411';

/**
 * @constant {String} XmlDsigGost2012Url256 Алгоритм подписи для XmlDsig.
 */
const XmlDsigGost2012Url256 = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256';

/**
 * @constant {String} XmlDsigGost2012Url256Digest Алгоритм подписи для XmlDsig.
 */
const XmlDsigGost2012Url256Digest = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256';

/**
 * @constant {String} XmlDsigGost2012Url512 Алгоритм подписи для XmlDsig.
 */
const XmlDsigGost2012Url512 = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512';

/**
 * @constant {String} XmlDsigGost2012Url512Digest Алгоритм подписи для XmlDsig.
 */
const XmlDsigGost2012Url512Digest = 'urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512';

/**
 * @constant {String} XmlDsigGost3410UrlObsolete Алгоритм подписи для XmlDsig.
 */
const XmlDsigGost3410UrlObsolete = 'http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411';

/**
 * @constant {String} XmlDsigGost3411UrlObsolete Алгоритм подписи для XmlDsig.
 */
const XmlDsigGost3411UrlObsolete = 'http://www.w3.org/2001/04/xmldsig-more#gostr3411';
/**
 * @constant {Number} LOG_LEVEL_DEBUG Уровень ведения логов DEBUG.
 */
const LOG_LEVEL_DEBUG = 4;

/**
 * @constant {Number} LOG_LEVEL_INFO Уровень ведения логов INFO.
 */
const LOG_LEVEL_INFO = 2;

/**
 * @constant {Number} LOG_LEVEL_ERROR Уровень ведения логов ERROR.
 */
const LOG_LEVEL_ERROR = 1;
/**
 * @constant {Object} Справочник общих полей в подписи
 */
const COMMON_FIELDS = {
    'UnstructuredName=': 'Неструктурированное имя',
    'E=': 'Email',
    'C=': 'Страна',
    'S=': 'Регион',
    'L=': 'Город',
    'STREET=': 'Адрес',
    'O=': 'Компания',
    'T=': 'Должность',
    'ОГРНИП=': 'ОГРНИП',
    'OGRNIP=': 'ОГРНИП',
    'SNILS=': 'СНИЛС',
    'СНИЛС=': 'СНИЛС',
    'INN=': 'ИНН',
    'ИНН=': 'ИНН',
    'ОГРН=': 'ОГРН',
    'OGRN=': 'ОГРН',
};

/**
 * @constant {Object} Справочник полей SUBJECT
 */
const SUBJECT_FIELDS = {
    'SN=': 'Фамилия',
    'G=': 'Имя/Отчество',
    'CN=': 'Владелец',
    'OU=': 'Отдел/подразделение',
};

/**
 * @constant {Object} Справочник полей ISSUER
 */
const ISSUER_FIELDS = {
    'CN=': 'Удостоверяющий центр',
    'OU=': 'Тип',
};
/**
 * @description объект для создания асинхроннного/синхранного объекта методом cadesplugin
 */
class CadesBaseMethods {
    /**
     * @param {Object} args объект инициализирующих значений
     * @description метод-конструктор
     */
    constructor(args) {
        this.O_STORE = args.O_STORE;
        this.O_ATTS = args.O_ATTS;
        this.O_SIGNED_DATA = args.O_SIGNED_DATA;
        this.O_SIGNER = args.O_SIGNER;
        this.O_SIGNED_XML = args.O_SIGNED_XML;
        this.O_ABOUT = args.O_ABOUT;
        this.O_RAW_SIGNATURE = args.O_RAW_SIGNATURE;
        this.O_HASHED_DATA = args.O_HASHED_DATA;
    }

    /**
     * @async
     * @method createObject
     * @param {String} method
     * @returns {Method}
     * @description выбирает доступный метод для текущего браузера
     */
    async createObject(method) {
        const supportedMethod = (await window.cadesplugin.CreateObject) ?
            await window.cadesplugin.CreateObject(method) :
            await window.cadesplugin.CreateObjectAsync(method);

        return supportedMethod;
    }

    /**
     * @method oStore
     * @returns {Object}
     * @description возвращает созданный объект
     */
    oStore() {
        return this.createObject(this.O_STORE);
    }

    /**
     * @method oAtts
     * @returns {Object}
     * @description возвращает созданный объект
     */
    oAtts() {
        return this.createObject(this.O_ATTS);
    }

    /**
     * @method oSignedData
     * @returns {Object}
     * @description возвращает созданный объект
     */
    oSignedData() {
        return this.createObject(this.O_SIGNED_DATA);
    }

    /**
     * @method oSigner
     * @returns {Object}
     * @description возвращает созданный объект
     */
    oSigner() {
        return this.createObject(this.O_SIGNER);
    }

    /**
     * @method oSignedXml
     * @returns {Object}
     * @description возвращает созданный объект
     */
    oSignedXml() {
        return this.createObject(this.O_SIGNED_XML);
    }

    /**
     * @method oAbout
     * @returns {Object}
     * @description возвращает созданный объект
     */
    oAbout() {
        return this.createObject(this.O_ABOUT);
    }

    /**
     * @method oRawSignature
     * @returns {Object}
     * @description возвращает созданный объект
     */
    oRawSignature() {
        return this.createObject(this.O_RAW_SIGNATURE);
    }

    /**
     * @method oAbout
     * @returns {Object}
     * @description возвращает созданный объект
     * @see http://cpdn.cryptopro.ru/?url=/content/cades/class_c_ad_e_s_c_o_m_1_1_c_p_signers.html
     */
    oHashedData() {
        return this.createObject(this.O_HASHED_DATA);
    }
}

/**
 * @inheritdoc
 */
const cadescomMethods = new CadesBaseMethods({
    O_STORE: 'CAdESCOM.Store',
    O_ATTS: 'CADESCOM.CPAttribute',
    O_SIGNED_DATA: 'CAdESCOM.CadesSignedData',
    O_SIGNER: 'CAdESCOM.CPSigner',
    O_SIGNED_XML: 'CAdESCOM.SignedXML',
    O_ABOUT: 'CAdESCOM.About',
    O_RAW_SIGNATURE: 'CAdESCOM.RawSignature',
    O_HASHED_DATA: 'CAdESCOM.HashedData',
});

/**
 * @description объект, в котором собираются данные о сертификате и методы по работе с этими данными
 */
class CertificateAdjuster {
    constructor(data) {
        const {
            certApi,
            issuerInfo,
            privateKey,
            serialNumber,
            thumbprint,
            subjectInfo,
            validPeriod
        } = data;

        this.certApi = certApi;
        this.issuerInfo = issuerInfo;
        this.privateKey = privateKey;
        this.serialNumber = serialNumber;
        this.thumbprint = thumbprint;
        this.subjectInfo = subjectInfo;
        this.validPeriod = validPeriod;
    }

    /**
     * @method friendlyInfo
     * @param {String} subjectIssuer раздел информации 'issuerInfo' или 'subjectInfo'
     * @returns {Object}
     * @throws {Error}
     * @description возврящает объект из сформированных значений
     */
    friendlyInfo(subjectIssuer) {
        if (!this[subjectIssuer]) {
            throw new Error('Не верно указан аттрибут');
        }

        const subjectIssuerArr = this[subjectIssuer].split(', ');

        let fields = {};

        switch (subjectIssuer) {
            case 'subjectInfo':
                fields = {
                    ...COMMON_FIELDS,
                    ...SUBJECT_FIELDS,
                };
            case 'issuerInfo':
                fields = {
                    ...COMMON_FIELDS,
                    ...ISSUER_FIELDS,
                };
                break
        }

        const formedSubjectIssuerInfo = subjectIssuerArr.map(tag => {
            const tagArr = tag.split('=');
            const index = `${tagArr[0]}=`;

            return {
                code: tagArr[0],
                text: tagArr[1],
                value: fields[index] ? fields[index] : '',
            };
        });

        return formedSubjectIssuerInfo;
    }

    /**
     * @method friendlySubjectInfo
     * @returns {Array}
     * @description возвращает распаршенную информацию о строке subjectInfo
     */
    friendlySubjectInfo() {
        return this.friendlyInfo('subjectInfo');
    }

    /**
     * @method friendlyIssuerInfo
     * @returns {Array}
     * @description возвращает распаршенную информацию о строке issuerInfo
     */
    friendlyIssuerInfo() {
        return this.friendlyInfo('issuerInfo');
    }

    /**
     * @method friendlyValidPeriod
     * @returns {Object}
     * @description возвращает распаршенную информацию об объекте validPeriod
     */
    friendlyValidPeriod() {
        const {
            from,
            to
        } = this.validPeriod;

        return {
            from: this.friendlyDate(from),
            to: this.friendlyDate(to),
        };
    }

    /**
     * @function friendlyDate
     * @param {String} date строка с датой
     * @returns {Object}
     * @description формирует дату от переданного параметра
     * @todo padStart 2
     */
    friendlyDate(date) {
        const newDate = new Date(date);
        const [day, month, year] = [newDate.getDate(), newDate.getMonth() + 1, newDate.getFullYear()];
        const [hours, minutes, seconds] = [newDate.getHours(), newDate.getMinutes(), newDate.getSeconds()];

        return {
            ddmmyy: `${day}/${month}/${year}`,
            hhmmss: `${hours}:${minutes}:${seconds}`,
        };
    }

    /**
     * @async
     * @method isValid
     * @returns {Boolean} возвращает валидность сертификата
     * @throws {Error} возвращает сообщение об ошибке
     * @description прозиводит проверку на валидность сертификата
     */
    async isValid() {
        try {
            const isValid = await this.certApi.IsValid();

            return await isValid.Result;
        } catch (error) {
            throw new Error(`Произошла ошибка при проверке валидности сертификата: ${error.message}`);
        }
    }
}

/**
 * @async
 * @function currentCadesCert
 * @param {String} thumbprint значение сертификата
 * @throws {Error}
 * @description получает сертификат по thumbprint значению сертификата
 */
async function currentCadesCert(thumbprint) {
    try {
        if (!thumbprint) {
            throw new Error('Не указано thumbprint значение сертификата');
        } else if (typeof thumbprint !== 'string') {
            throw new Error('Не валидное значение thumbprint сертификата');
        }
        const oStore = await cadescomMethods.oStore();

        await oStore.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

        const certificates = await oStore.Certificates;
        const count = await certificates.Count;
        const findCertificate = await certificates.Find(CAPICOM_CERTIFICATE_FIND_SHA1_HASH, thumbprint);
        if (count) {
            const certificateItem = await findCertificate.Item(1);
            oStore.Close();

            return certificateItem;
        } else {
            throw new Error(`Произошла ошибка при получении вертификата по thumbprint значению: ${thumbprint}`);
        }
    } catch (error) {
        throw new Error(error.message);
    }
}

/**
 * @async
 * @function getCertsList
 * @throws {Error}
 * @description получает массив активных сертификатов
 */
async function getCertsList() {
    try {
        const oStore = await cadescomMethods.oStore();
        await oStore.Open(CAPICOM_CURRENT_USER_STORE, CAPICOM_MY_STORE, CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

        const certificates = await oStore.Certificates;

        if (!certificates) {
            throw new Error('Нет доступных сертификатов');
        }

        const findCertificate = await certificates.Find(CAPICOM_CERTIFICATE_FIND_TIME_VALID);
        const findCertsWithPrivateKey = await findCertificate.Find(
            CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY,
            CAPICOM_PROPID_KEY_PROV_INFO
        );

        const count = await findCertsWithPrivateKey.Count;

        if (!count) {
            throw new Error('Нет сертификатов с приватным ключём');
        }

        const countArray = Array(count).fill(null);

        const createCertList = await Promise.all(
            /**
             * @async
             * @function
             * @prop {Null} _ неиспользуемая величина
             * @prop {Number} index
             * Порядок элемента в массиве.
             * В функции используется index + 1, так как в cadesplugin счёт элементов ведётся с 1, а в итераторе с 0
             * @description итерируемая асинхронная функция, возвращающая массив из промисов
             */
            countArray.map(async (_, index) => {
                try {
                    const certApi = await findCertsWithPrivateKey.Item(index + 1);

                    const сertificateAdjuster = new CertificateAdjuster({
                        certApi,
                        issuerInfo: await certApi.IssuerName,
                        privateKey: await certApi.PrivateKey,
                        serialNumber: await certApi.SerialNumber,
                        subjectInfo: await certApi.SubjectName,
                        thumbprint: await certApi.Thumbprint,
                        validPeriod: {
                            from: await certApi.ValidFromDate,
                            to: await certApi.ValidToDate,
                        },
                    });

                    return сertificateAdjuster;
                } catch (error) {
                    throw new Error(`При переборе сертификатов произошла ошибка: ${error.message}`);
                }
            })
        );

        oStore.Close();

        return createCertList;
    } catch (error) {
        throw new Error(error.message);
    }
}

/**
 * @async
 * @function getFirstValidCertificate
 * @throws {Error}
 * @description получает первый валидный сертификат
 */
async function getFirstValidCertificate() {
    try {
        const certList = await getCertsList();

        for (let index = 0; index < certList.length; index++) {
            let validation = await certList[index].certApi.IsValid();
            let isValid = await validation.Result;

            if (isValid) {
                return await certList[index];
            }
        }

        throw new Error(`Нет сертификатов, подходящих для подписи`);
    } catch (error) {
        throw new Error(error.message);
    }
}

/**
 * @async
 * @function signFile
 * @param {String} thumbprint значение сертификата
 * @param {String} base64 файл - base64
 * @param {Boolean} type тип подписи true=откреплённая false=прикреплённая
 * @param {Number} signOption опции сертификата @default CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN
 *      0 CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT Сохраняет все сертификаты цепочки за исключением корневого.
 *      1 CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN Сохраняет полную цепочку.
 *      2 CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY Сертификат включает только конечное лицо
 * @throws {Error}
 * @description подпись строки в формате base64
 */
async function signFile(thumbprint, base64, type = true, signOption = CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN) {
    try {
        if (!thumbprint) {
            throw new Error('Не указано thumbprint значение сертификата');
        } else if (typeof thumbprint !== 'string') {
            throw new Error('Не валидное значение thumbprint сертификата');
        }

        const oDateAttrs = await cadescomMethods.oAtts();
        const oSignedData = await cadescomMethods.oSignedData();
        const oSigner = await cadescomMethods.oSigner();
        const currentCert = await currentCadesCert(thumbprint);
        const authenticatedAttributes2 = await oSigner.AuthenticatedAttributes2;

        await oDateAttrs.propset_Name(CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME);
        await oDateAttrs.propset_Value(new Date());
        await authenticatedAttributes2.Add(oDateAttrs);

        await oSignedData.propset_ContentEncoding(CADESCOM_BASE64_TO_BINARY);
        await oSignedData.propset_Content(base64);

        await oSigner.propset_Certificate(currentCert);
        await oSigner.propset_Options(signOption);

        return await oSignedData.SignCades(oSigner, CADESCOM_CADES_BES, type);
    } catch (error) {
        throw new Error(error.message);
    }
}

async function signThe(file) {
    try {
        console.log('Поиск сертификата...')
        const certificate = await getFirstValidCertificate();
        console.log('Подпись...')
        const signature = await signFile(certificate.thumbprint, file, true, 1);
        // true=откреплённая подпись false=прикреплённая подпись.
        // 0 CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT Сохраняет все сертификаты цепочки за исключением корневого.
        // 1 CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN Сохраняет полную цепочку.
        // 2 CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY Сертификат включает только конечное лицо
        console.log(signature);
    } catch (error) {
        console.log(error.message);
    }
}
