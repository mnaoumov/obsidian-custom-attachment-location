export const tr = {
  attachmentCollector: {
    confirm: 'Klasörlerdeki tüm notlar için ekleri alt klasörlerle birlikte toplamak ister misiniz?\n{{folders}}\nBu işlem geri alınamaz.',
    progressBar: {
      message: 'Ekler toplanıyor {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Ekler toplanıyor...'
    }
  },
  buttons: {
    copy: 'Kopyala',
    move: 'Taşı',
    previewAttachmentFile: 'Ek dosyasını önizle',
    skip: 'Geç'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: '{{attachment}} eki birden fazla not tarafından referans alınıyor.',
    heading: 'Birden fazla not tarafından kullanılan ek toplama',
    noPriorityWinnerReason: {
      EmptyList: '{{settingName}} ayarı boş olduğu için taşınmadı; bu notlardan hangisinin sahibi olduğuna karar veren bir şey yok.',
      NoMatch: 'Bu notların hiçbiri {{settingName}} ayarındaki hiçbir girdiyle eşleşmediği için taşınmadı.',
      Tie: 'Bu notların birkaçı {{settingName}} ayarıyla eşit derecede eşleştiği ve tek bir sahip belirlenemediği için taşınmadı.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Diğer sorunlu ekler için aynı eylemi kullanılmalı'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Mevcut klasördeki ekleri topla',
    collectAttachmentsCurrentNote: 'Mevcut nottaki ekleri topla',
    collectAttachmentsEntireVault: 'Tüm kasadaki ekleri topla'
  },
  links: {
    documentation: 'dokümantasyona',
    tokens: 'tokenlara'
  },
  menuItems: {
    collectAttachmentsInFile: 'Dosyada ekleri topla',
    collectAttachmentsInFiles: 'Dosyalarda ekleri topla'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: '\'{{noteFilePath}}\' için ekler toplanıyor',
    collectingAttachmentsCancelled: 'Ek toplama işlemi iptal edildi. Ayrıntılar için konsola bakın.',
    generatedAttachmentFileNameIsInvalid: 'Oluşturulan ek dosya adı \'{{path}}\' geçersiz.\n{{validationMessage}}\n{{settingName}} ayarınızı kontrol edin.',
    notePathIsIgnored: 'Not yolu yok sayıldı'
  },
  obsidianLib: {
    buttons: {
      cancel: 'İptal',
      ok: 'Tamam'
    },
    dataview: {
      itemsPerPage: 'Sayfa başına öğe:',
      jumpToPage: 'Sayfaya git:'
    },
    notices: {
      attachmentIsStillUsed: 'Ek {{attachmentPath}} hala diğer notlar tarafından kullanılıyor. Silinmeyecek.',
      unhandledError: 'İşlenmemiş bir hata oluştu. Lütfen detaylar için konsolu kontrol edin.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'Tüm dosyaların adı değiştirilecek.',
        displayText: 'Tümü'
      },
      none: {
        description: 'Dosya isimleri korunacak.',
        displayText: 'Hiçbiri'
      },
      onlyPastedImages: {
        description: 'Yalnızca yapıştırılan PNG görüntülerinin isimleri değiştirilecek. Genellikle ekran görüntüsü yapıştırmak için kullanılır.',
        displayText: 'Yalnızca yapıştırılan görüntüler'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'Ek toplama işlemini iptal et.',
        displayText: 'İptal'
      },
      copy: {
        description: 'Eki yeni konuma kopyala.',
        displayText: 'Kopyala'
      },
      move: {
        description: 'Eki yeni konuma taşı.',
        displayText: 'Taşı'
      },
      prompt: {
        description: 'Kullanıcıdan işlem seçmesini iste.',
        displayText: 'İste'
      },
      skip: {
        description: 'Eki atla ve sonraki ekleme geç.',
        displayText: 'Atla'
      }
    },
    defaultImageSizeDimension: {
      height: 'Yükseklik',
      width: 'Genişlik'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Özel tokenler yorum satırı yapıldı, 9.0.0 sürümünde değişen formata güncellenmesi gerekiyor.\n// Daha fazla bilgi için dokümantasyona ({{customTokensDocumentationUrl}}) bakınız.',
      deprecated: 'Özel token kayıt formatı değişti. Lütfen tokenlarınızı buna göre güncelleyin. Daha fazla bilgi için {{documentation}} bakın.'
    },
    legacyRenameAttachmentsToLowerCase: '{{setting}} ayarı kullanımdan kaldırıldı. Bunun yerine {{format}} formatını kullanın. Daha fazla bilgi için {{documentation}} bakın.',
    markdownUrlFormat: {
      deprecated: '{{setting}} formatı için muhtemelen hatalı bir değer ayarladınız. Daha fazla bilgi için lütfen {{documentation}} bakın. Bu mesaj tekrar gösterilmeyecek.'
    },
    specialCharacters: '{{setting}} ayarının varsayılan değeri değişti. Ayar değeriniz yeni varsayılan değere güncellendi.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Varsayılan resim boyutu piksel veya yüzde olmalıdır',
      invalidCustomTokensCode: 'Geçersiz özel token kodu',
      invalidRegularExpression: 'Geçersiz düzenli ifade {{regExp}}',
      specialCharactersMustNotContainSlash: 'Özel karakterler / içermemelidir',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Özel karakterler geçersiz dosya adı veya yol karakterleri içermemelidir'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Dosya eklerken:',
      name: 'Ek dosya yeniden adlandırma modu'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Toplanan ek birden fazla notta kullanıldığında:',
      name: 'Birden fazla notta kullanılan ek toplama modu'
    },
    collectedAttachmentFileName: {
      description: 'Kullanılabilir {{tokens}} göz atın.\nEkin mevcut dosya adını korumak için boş bırakın.',
      name: 'Toplanan ek dosya adı'
    },
    customTokens: {
      description: 'Kullanılacak özel tokenlar.\nDaha fazla bilgi için {{documentation}} bakın.\n⚠️ Özel tokenlar herhangi bir JavaScript kodu olabilir. Kötü yazılırsa veri kaybına yol açabilir. Kendi sorumluluğunuzda kullanın.',
      name: 'Özel tokenlar'
    },
    defaultImageSize: {
      description: 'Varsayılan resim boyutu.\nPiksel ({{pixels}}) veya tam resim boyutunun yüzdesi ({{percentage}}) olarak belirtilebilir.\nOrijinal resim boyutunu kullanmak için boş bırakın.',
      name: 'Varsayılan resim boyutu'
    },
    duplicateNameSeparator: {
      description: 'Mevcut bir dosyayla aynı ada sahip bir dosyayı yapıştırdığınızda veya sürüklediğinizde, bu ayırıcı dosya adına eklenir.\nÖrneğin {{existingFile}} dosyasını sürüklediğinizde, ilk kullanılabilir ad seçilerek {{firstAvailableName}}, {{secondAvailableName}} vb. olarak yeniden adlandırılır.',
      name: 'Yinelenen ad ayırıcı'
    },
    excludePathsFromAttachmentCollecting: {
      description: '{{command}} komutu çalıştırıldığında aşağıdaki yollardaki ekler hariç tutulur.\nHer yolu yeni bir satıra yazın.\n{{pathSyntax}}\nAyar boşsa, ek toplamadan hiçbir yol hariç tutulmaz.',
      name: 'Ek toplarken hariç tutulan yollar'
    },
    generatedAttachmentFileName: {
      description: 'Kullanılabilir {{tokens}} göz atın.',
      name: 'Oluşturulan ek dosya adı'
    },
    jpegQuality: {
      description: 'Kalite ne kadar düşükse, sıkıştırma oranı o kadar yüksek olur.',
      name: 'JPEG Kalitesi'
    },
    locationForNewAttachments: {
      description: 'Notun üst klasörüne göreceli yollar için {{relativePrefix}} ile başlayın.\nKullanılabilir {{tokens}} göz atın.\n{{dotFolder}} gibi nokta ile başlayan klasörler önerilmez, çünkü Obsidian bunları takip etmez. Bunları yönetmek için {{unhidePlugin}} eklentisini kullanmanız gerekebilir.',
      name: 'Yeni ekler için konum'
    },
    markdownUrlFormat: {
      description: 'Bir ek eklendiğinde Markdown içine eklenecek URL formatı. Yalnızca o anda uygulanır: bir not veya ek yeniden adlandırıldığında ya da taşındığında Obsidian\'ın daha sonra yeniden yazdığı bağlantı varsayılan formatı alır.\nKullanılabilir {{tokens}} göz atın.\nVarsayılan formatı kullanmak için boş bırakın.',
      name: 'Markdown URL formatı'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Ek klasörü ve dosya adı ayarlarının, BAŞKA eklentilerin oluşturduğu eklere de uygulanıp uygulanmayacağı.\nBazı eklentiler, nereye ait olduğunu Obsidian\'a sormadan eki kendi seçtikleri bir adla doğrudan kasaya yazar. Bu seçenek açıkken böyle bir dosya, ortaya çıkar çıkmaz taşınır ve yeniden adlandırılır.\nYalnızca bir not açıkken oluşturulan ve bir nottan bağlantı verilen dosyalara dokunulur: hiçbir notun bağlantı vermediği bir dosya, başka bir eklentinin kendisi için sakladığı veridir ve yazıldığı yerde kalır. Eşitlemeden veya kasa içe aktarımından gelen dosyalara asla dokunulmaz.\n{{modes}}\nDosyayı oluşturan eklenti, yazma işleminin çağrı yığınından belirlenir. Bu en iyi çaba esasına dayanır: Obsidian\'ın kendisinin, bir eşitleme istemcisinin veya yazmayı erteleyen bir eklentinin yazdığı dosya için hiçbir eklenti belirlenemez. Böyle bir dosya aşağıdaki listede YOK sayılır.',
      name: 'Diğer eklentilerin oluşturduğu ekleri yeniden adlandır'
    },
    renameAttachmentsToLowerCase: 'Eklerin dosya adlarını küçük harfe çevir',
    renamedAttachmentFileName: {
      description: 'Kullanılabilir {{tokens}} göz atın.\nEkin mevcut dosya adını korumak için boş bırakın.',
      name: 'Yeniden adlandırılan ek dosya adı'
    },
    resetToSampleCustomTokens: {
      message: 'Özel tokenları örnek tokenlara sıfırlamak istediğinize emin misiniz? Değişiklikleriniz kaybolacak.',
      title: 'Örnek tokenlara sıfırla'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Yapıştırılan görüntülerin JPEG\'e dönüştürülüp dönüştürülmeyeceği. Sadece PNG içeriği direkt olarak pano’dan yapıştırıldığında geçerlidir. Genellikle ekran görüntüleri için.',
      name: 'Yapıştırılan görüntüleri JPEG\'e dönüştür'
    },
    shouldRenameCollectedAttachments: {
      description: 'Etkinse, {{command}} komutlarıyla işlenen ekler {{setting}} ayarına göre yeniden adlandırılır.',
      name: 'Toplanan ek dosyalarını yeniden adlandır'
    },
    specialCharacters: {
      description: 'Ek klasörü ve dosya adında değiştirilecek veya kaldırılacak özel karakterler.\nÖzel karakterleri korumak için boş bırakın.',
      name: 'Özel karakterler'
    },
    specialCharactersReplacement: {
      description: 'Ek klasörü ve dosya adındaki özel karakterler için değiştirme dizesi.\nÖzel karakterleri kaldırmak için boş bırakın.',
      name: 'Özel karakterler için değiştirme'
    },
    timeoutInSeconds: {
      description: 'Tüm işlemler için zaman aşımı süresi (saniye).\n{{zero}} ayarlanırsa, işlemlerin zaman aşımı devre dışı bırakılır.',
      name: 'Zaman aşımı (saniye)'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Ek dosyasını yeniden adlandır',
    folderTitle: 'Ek klasörünü seç',
    previewModal: {
      title: 'Ek dosyasını önizle \'{{fullFileName}}\''
    },
    title: 'İstem tokenı için bir değer girin'
  },
  regularExpression: '/düzenli ifade/'
};
