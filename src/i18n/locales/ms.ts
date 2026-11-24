export const ms = {
  attachmentCollector: {
    confirm: 'Adakah anda mahu mengumpul lampiran untuk semua nota dalam folder berikut secara rekursif?\n{{folders}}\nOperasi ini tidak boleh dibatalkan.',
    progressBar: {
      message: 'Mengumpul lampiran {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Mengumpul lampiran...'
    }
  },
  buttons: {
    copy: 'Salin',
    move: 'Pindah',
    previewAttachmentFile: 'Pratonton fail lampiran',
    skip: 'Langkau'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Lampiran {{attachment}} dirujuk oleh beberapa nota.',
    heading: 'Mengumpul lampiran yang digunakan oleh beberapa nota',
    noPriorityWinnerReason: {
      EmptyList: 'Ia tidak dipindahkan kerana tetapan {{settingName}} kosong, jadi tiada apa-apa yang menentukan nota mana yang memilikinya.',
      NoMatch: 'Ia tidak dipindahkan kerana tiada satu pun daripada nota ini sepadan dengan mana-mana entri dalam tetapan {{settingName}}.',
      Tie: 'Ia tidak dipindahkan kerana beberapa daripada nota ini sepadan dengan tetapan {{settingName}} sama baiknya, jadi ia tidak menamakan satu pemilik.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Patut menggunakan tindakan yang sama untuk lampiran bermasalah lain'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Kumpul lampiran dalam folder semasa',
    collectAttachmentsCurrentNote: 'Kumpul lampiran dalam nota semasa',
    collectAttachmentsEntireVault: 'Kumpul lampiran dalam keseluruhan vault'
  },
  links: {
    documentation: 'dokumentasi',
    tokens: 'token'
  },
  menuItems: {
    collectAttachmentsInFile: 'Kumpul lampiran dalam fail',
    collectAttachmentsInFiles: 'Kumpul lampiran dalam fail-fail'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Mengumpul lampiran untuk \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Pengumpulan lampiran dibatalkan. Lihat konsol untuk butiran.',
    generatedAttachmentFileNameIsInvalid: 'Nama fail lampiran yang dijana \'{{path}}\' tidak sah.\n{{validationMessage}}\nSemak tetapan {{settingName}} anda.',
    notePathIsIgnored: 'Laluan nota diabaikan'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Batal',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Item per halaman:',
      jumpToPage: 'Lompat ke halaman:'
    },
    notices: {
      attachmentIsStillUsed: 'Lampiran {{attachmentPath}} masih digunakan oleh nota lain. Ia tidak akan dipadamkan.',
      unhandledError: 'Ralat yang tidak diuruskan berlaku. Sila semak konsol untuk maklumat lanjut.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'semua fail akan dinamakan semula.',
        displayText: 'Semua'
      },
      none: {
        description: 'nama mereka dipelihara.',
        displayText: 'Tiada'
      },
      onlyPastedImages: {
        description: 'hanya imej yang ditampal akan dinamakan semula. Berlaku hanya apabila kandungan imej PNG ditampal terus dari papan keratan. Biasanya, untuk menampal tangkapan skrin.',
        displayText: 'Hanya imej yang ditampal'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'batalkan pengumpulan lampiran.',
        displayText: 'Batal'
      },
      copy: {
        description: 'salin lampiran ke lokasi baru.',
        displayText: 'Salin'
      },
      move: {
        description: 'pindahkan lampiran ke lokasi baru.',
        displayText: 'Pindah'
      },
      prompt: {
        description: 'minta pengguna memilih tindakan.',
        displayText: 'Minta'
      },
      skip: {
        description: 'langkau lampiran dan teruskan ke yang seterusnya.',
        displayText: 'Langkau'
      }
    },
    defaultImageSizeDimension: {
      height: 'Ketinggian',
      width: 'Kelebaran'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Token kustom telah dikomenkan kerana perlu dikemas kini ke format baharu yang diperkenalkan dalam versi pemalam 9.0.0.\n// Rujuk dokumentasi ({{customTokensDocumentationUrl}}) untuk maklumat lanjut.',
      deprecated: 'Format pendaftaran token kustom telah berubah. Sila kemas kini token anda dengan sewajarnya. Rujuk {{documentation}} untuk maklumat lanjut.'
    },
    legacyRenameAttachmentsToLowerCase: 'Tetapan {{setting}} tidak digunakan lagi. Gunakan format {{format}} sebagai gantinya. Lihat {{documentation}} untuk maklumat lanjut.',
    markdownUrlFormat: {
      deprecated: 'Anda mungkin telah menetapkan nilai yang tidak betul untuk format {{setting}}. Sila rujuk {{documentation}} untuk maklumat lanjut. Mesej ini tidak akan dipaparkan lagi.'
    },
    specialCharacters: 'Nilai lalai tetapan {{setting}} telah berubah. Nilai tetapan anda telah dikemas kini ke nilai lalai baharu.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Saiz imej lalai mesti dalam piksel atau peratusan',
      invalidCustomTokensCode: 'Kod token kustom tidak sah',
      invalidRegularExpression: 'Ungkapan biasa tidak sah {{regExp}}',
      specialCharactersMustNotContainSlash: 'Aksara khas tidak boleh mengandungi /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Penggantian aksara khas tidak boleh mengandungi aksara laluan nama fail yang tidak sah.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Apabila melampirkan fail:',
      name: 'Mod penamaan semula lampiran'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Apabila lampiran yang dikumpulkan digunakan oleh beberapa nota:',
      name: 'Mod pengumpulan lampiran yang digunakan oleh beberapa nota'
    },
    collectedAttachmentFileName: {
      description: 'Lihat {{tokens}} yang tersedia.\nBiarkan kosong untuk mengekalkan nama fail semasa lampiran.',
      name: 'Nama fail lampiran yang dikumpulkan'
    },
    customTokens: {
      description: 'Token kustom yang akan digunakan.\nLihat {{documentation}} untuk maklumat lanjut.\n⚠️ Token kustom boleh menjadi sebarang kod JavaScript. Jika ditulis dengan buruk, ia boleh menyebabkan kehilangan data. Gunakan dengan risiko sendiri.',
      name: 'Token kustom'
    },
    defaultImageSize: {
      description: 'Saiz imej lalai.\nBoleh dinyatakan dalam piksel ({{pixels}}) atau sebagai peratusan daripada saiz imej penuh ({{percentage}}).\nBiarkan kosong untuk menggunakan saiz imej asal.',
      name: 'Saiz imej lalai'
    },
    duplicateNameSeparator: {
      description: 'Apabila anda menampal atau menyeret fail dengan nama yang sama seperti fail sedia ada, pemisah ini akan ditambah pada nama fail.\nContohnya, apabila anda menyeret fail {{existingFile}}, ia akan dinamakan semula kepada {{firstAvailableName}}, {{secondAvailableName}} dan seterusnya, mengikut nama pertama yang tersedia.',
      name: 'Pemisah nama pendua'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Kecualikan lampiran dari laluan berikut apabila arahan {{command}} dilaksanakan.\nMasukkan setiap laluan pada baris baru.\n{{pathSyntax}}\nJika tetapan kosong, tiada laluan dikecualikan dari pengumpulan lampiran.',
      name: 'Kecualikan laluan dari pengumpulan lampiran'
    },
    generatedAttachmentFileName: {
      description: 'Lihat {{tokens}} yang tersedia.',
      name: 'Nama fail lampiran yang dijana'
    },
    jpegQuality: {
      description: 'Semakin kecil kualiti, semakin besar nisbah mampatan.',
      name: 'Kualiti JPEG'
    },
    locationForNewAttachments: {
      description: 'Mulakan dengan {{relativePrefix}} untuk laluan relatif kepada folder induk nota.\nLihat {{tokens}} yang tersedia.\nFolder titik seperti {{dotFolder}} tidak disyorkan, kerana Obsidian tidak menjejakinya. Anda mungkin perlu menggunakan pemalam {{unhidePlugin}} untuk mengurusnya.',
      name: 'Lokasi untuk lampiran baharu'
    },
    markdownUrlFormat: {
      description: 'Format untuk URL yang akan dimasukkan ke dalam Markdown apabila lampiran ditambah. Ia hanya dikenakan pada saat itu: pautan yang ditulis semula oleh Obsidian kemudian, apabila nota atau lampiran dinamakan semula atau dipindahkan, mendapat format lalai.\nLihat {{tokens}} yang tersedia.\nBiarkan kosong untuk menggunakan format lalai.',
      name: 'Format URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description:
        'Sama ada tetapan folder lampiran dan nama fail dikenakan pada lampiran yang dicipta oleh pemalam LAIN.\nSesetengah pemalam menulis lampiran ke dalam bilik kebal dengan nama pilihan sendiri, tanpa bertanya kepada Obsidian di mana tempatnya. Dengan ini dihidupkan, fail sebegitu dipindahkan dan dinamakan semula sebaik ia muncul.\nHanya fail yang dicipta semasa sesuatu nota dibuka, dan dipautkan dari sesuatu nota, akan disentuh: fail yang tidak dipautkan oleh mana-mana nota ialah data yang disimpan oleh pemalam lain untuk dirinya sendiri, dan kekal di tempat ia ditulis. Fail yang tiba daripada penyegerakan atau import bilik kebal tidak pernah disentuh.\n{{modes}}\nPemalam yang mencipta fail dikenal pasti daripada timbunan panggilan penulisan itu. Ini dilakukan sebaik mungkin: tiada pemalam dikenal pasti bagi fail yang ditulis oleh Obsidian sendiri, oleh klien penyegerakan, atau oleh pemalam yang menangguhkan penulisannya. Fail sebegitu dikira sebagai TIDAK berada dalam senarai di bawah.',
      name: 'Namakan semula lampiran yang dicipta pemalam lain'
    },
    renameAttachmentsToLowerCase: 'Nama semula lampiran kepada huruf kecil',
    renamedAttachmentFileName: {
      description: 'Lihat {{tokens}} yang tersedia.\nBiarkan kosong untuk mengekalkan nama fail semasa lampiran.',
      name: 'Nama fail lampiran yang dinamakan semula'
    },
    resetToSampleCustomTokens: {
      message: 'Adakah anda pasti mahu menetapkan semula token kustom kepada token kustom sampel? Perubahan anda akan hilang.',
      title: 'Tetapkan semula kepada token kustom sampel'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Sama ada untuk menukar imej yang ditampal kepada JPEG. Berlaku hanya apabila kandungan imej PNG ditampal terus dari papan keratan. Biasanya, untuk menampal tangkapan skrin.',
      name: 'Sama ada menukar imej yang ditampal kepada JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Jika diaktifkan, lampiran yang diproses melalui arahan {{command}} akan dinamakan semula mengikut tetapan {{setting}}.',
      name: 'Sama ada menamakan semula lampiran yang dikumpulkan'
    },
    specialCharacters: {
      description: 'Aksara khas dalam folder lampiran dan nama fail yang akan diganti atau dialihkan.\nBiarkan kosong untuk memelihara aksara khas.',
      name: 'Aksara khas'
    },
    specialCharactersReplacement: {
      description: 'Rentetan penggantian untuk aksara khas dalam folder lampiran dan nama fail.\nBiarkan kosong untuk mengalihkan aksara khas.',
      name: 'Penggantian aksara khas'
    },
    timeoutInSeconds: {
      description: 'Masa tamat dalam saat untuk semua operasi.\nJika {{zero}} ditetapkan, masa tamat pelaksanaan operasi dilumpuhkan.',
      name: 'Masa tamat dalam saat'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Namakan semula fail lampiran',
    folderTitle: 'Pilih folder lampiran',
    previewModal: {
      title: 'Pratonton fail lampiran \'{{fullFileName}}\''
    },
    title: 'Berikan nilai untuk token prompt'
  },
  regularExpression: '/ungkapan biasa/'
};
